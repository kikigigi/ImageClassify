from flask import Flask, jsonify, request
from flask_restful import Resource, Api
from pymongo import MongoClient
import bcrypt
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition
users = db['Users']

class Register(Resource):
    # Step 1 - Got posted data
    # Step 2 - Check if username has existed
    # Step 3 - Encrypt password
    # Step 3 - Add username and encrypted password to db
    def post(self):
        # Step 1
        data = request.get_json()
        username = data['username']

        # Step 2
        if userExist(username):
            return message('Invalid username!', 301)

        # Step 3
        password = data['password']
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Step 4
        users.insert({'Username':username,
                      'Password': hashed_pw,
                      'Tokens': 4})
        return message('User has been registered successfully', 200)



class ImageClassify(Resource):
    def post(self):
        # Step 1 - Get posted data
        # Step 2 - Verify credentials and tokens
        # Step 3 - Classify Image

        # Step 1
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Step 2
        msg, error = verifyCredentials(username, password)
        if error:
            return message(msg)

        current_tokens = tokenBalance(username)
        if current_tokens == 0:
            return message('No more tokens, please refill!', True)

        # Step 3
        image_url = data['url']
        image = requests.get(image_url)
        retJson = {}
        with open('temp.jpg', 'wb') as f:
            f.write(image.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            ret = proc.communicate()[0]
            proc.wait()
            with open("text.txt") as f:
                retJson = json.load(f)

        users.update({'Username':username},
                     {'$set':{'Tokens':current_tokens -1}})
        return retJson


class Refill(Resource):
    # Step 1 - get posted data
    # Step 2 - verify username and admin passowrd
    # Step 3 - updata db

    def post(self):
        # For testing only
        admin_password = 'abc123'

        # Step 1
        data = request.get_json()
        username = data['username']

        # Step 2
        admin_pw = data['admin_pw']
        if not userExist(username):
            return message('Invalid username!', 301)

        if admin_pw != admin_password:
            return message('Invalid admin password!', 304)

        # Step 3
        amount = data['amount']
        current_tokens = tokenBalance(username)
        available_tokens = amount + current_tokens
        users.update({'Username':username},
                     {'$set':{'Tokens': available_tokens}})

        return message('Congretulation refill successfully! Available tokens is {}'.format(available_tokens), 200)


def message(msg, status):
    return jsonify({'message': msg, 'status': status})

def userExist(username):
    if users.count_documents({'Username':username}) != 0:
        return True
    return False

def correctPassword(username, password):
    if not userExist(username):
        return False
    hashed_pw = users.find({'Username':username})[0]['Password']
    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    return False

def tokenBalance(username):
    if not userExist(username):
        return message('Invalid username', 301)
    return users.find({'Username':username})[0]['Tokens']

def verifyCredentials(username, password):
    if not userExist(username):
        return message('Invalid username', 301), True

    if not correctPassword(username, password):
        return message('Invalid password', 302), True

    return None, False


api.add_resource(Register, "/register")
api.add_resource(ImageClassify, "/imageclassify")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(host="0.0.0.0")
