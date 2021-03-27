# Importing required libs
from flask import Flask, request
from flask_restful import Resource, Api, reqparse
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from urllib.parse import quote
from passlib.hash import pbkdf2_sha256 as sha256
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, get_jwt_identity,)

# Creating Flask app obj
app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

# JWT Secret key
app.config['JWT_SECRET_KEY'] = '\x00\xfb\xdfB\xbf\xcd\x7f|X\xcc\x81\x92U\x1c\xc7^\xe1\x99\xbb\xfd\x9b\x93\xe2\xd4'

# Mongo DB Name
app.config['MONGO_DBNAME'] = 'devdb'
app.config['MONGO_URI'] = "mongodb+srv://T0Ny:" + \
    quote("password") + \
    "@cluster0.rs8jo.mongodb.net/devdb?retryWrites=true&w=majority"

# Creating different objects
jwt = JWTManager(app)
api = Api(app)
mongo = PyMongo(app)

# Required arguments from Request for RegisterUser and LoginUser Resource
user_args = reqparse.RequestParser()
user_args.add_argument('first_name', type=str, help='First Name')
user_args.add_argument('last_name', type=str, help='Last Name')
user_args.add_argument(
    'email', type=str, help='Email is required', required=True)
user_args.add_argument('password', type=str,
                       help='Password is required', required=True)

# Handle /register POST
class RegisterUser(Resource):

    def post(self):
        try:
            args = user_args.parse_args()
            users = mongo.db.users
            if users.find_one({'email': args['email']}) == None:
                password = sha256.hash(args['password'])
                users.insert_one(
                    {'first_name': args['first_name'], 'last_name': args['last_name'], 'email': args['email'], 'password': password})
                return {'status': 'SUCCESS', 'message': "User {} successfully registered".format(users['first_name'])}, 201
            else:
                return {'status': 'ERROR', 'message': "User email exist"}, 201
        except Exception as e:
            return {'status': 'ERROR'}, 400

# Handle /login POST
class LoginUser(Resource):

    def post(self):
        try:
            args = user_args.parse_args()
            user = mongo.db.users.find_one_or_404({'email': args['email']})
            if sha256.verify(args['password'], user['password']):
                access_token = create_access_token(identity=user['email'])
                return {'status': 'SUCCESS', 'message': "Successfully Loged In",
                        'access_token': access_token, }, 201
            else:
                return {'status': 'FAILED', 'message': "Failed Loged In"}, 400
        except Exception as e:
            print(e)
            return {'status': 'ERROR'}, 400

# Required arguments from Request for Templates and Template Resource
template_args = reqparse.RequestParser()
template_args.add_argument('template_name', type=str,
                           help='Name of the Template is required', required=True)
template_args.add_argument(
    'subject', type=str, help='Subject of the Template is required', required=True)
template_args.add_argument(
    'body', type=str, help='Body of the Template is required', required=True)

# Handle /template GET POST
class Templates(Resource):
    decorators = [jwt_required()]
    def get(self):
        try:
            current_user = get_jwt_identity()
            templates = mongo.db.templates.find({ "user": current_user })
            return {'status': 'SUCCESS', 'templates': [
                {
                    'template_id': str(template['_id']),
                    'template_name': template['template_name'],
                    'subject': template['subject'],
                    'body': template['body']
                } for template in templates if template]}, 200
        except Exception as e:
            return {'status': 'ERROR'}, 400

    def post(self):
        try:
            current_user = get_jwt_identity()
            args = template_args.parse_args()
            templates = mongo.db.templates
            templates.insert_one({ 
                    'user': current_user,                    
                    'template_name': args['template_name'],
                    'subject': args['subject'], 
                    'body': args['body']
                })
            return {'status': 'SUCCESS', }, 201
        except Exception as e:
            return {'status': 'ERROR'}, 400

# Handle /template/<template_id> GET PUT DEL
class Template(Resource):
    decorators = [jwt_required()]
    def get(self, template_id):
        try:
            current_user = get_jwt_identity()
            template = mongo.db.templates.find_one_or_404(
                {"_id": ObjectId(template_id), "user": current_user})
            return {'status': 'SUCCESS',
                    'template': {
                        'template_id': str(template['_id']),
                        'template_name': template['template_name'],
                        'subject': template['subject'],
                        'body': template['body']
                    }}, 200
        except Exception as e:
            return {'status': 'ERROR'}, 400

    def put(self, template_id):
        try:
            current_user = get_jwt_identity()
            args = template_args.parse_args()
            template = mongo.db.templates.find_one_and_update(
                {"_id": ObjectId(template_id), "user": current_user},
                {"$set": {
                    'user': current_user,
                    'template_name': args['template_name'],
                    'subject': args['subject'], 
                    'body': args['body']}}
                )
            return {'status': 'SUCCESS',
                    'template': {
                        'template_id': str(template['_id']),
                        'template_name': template['template_name'],
                        'subject': template['subject'],
                        'body': template['body']
                    }
                    }, 201
        except Exception as e:
            return {'status': 'ERROR'}, 400

    def delete(self, template_id):
        try:
            current_user = get_jwt_identity()
            templates = mongo.db.templates.find_one_and_delete(
                {"_id": ObjectId(template_id), "user": current_user})
            return {'status': 'SUCCESS'}, 204
        except Exception as e:
            return {'status': 'ERROR'}, 400

# Adding resouces with Route
api.add_resource(RegisterUser, '/register')
api.add_resource(LoginUser, '/login')
api.add_resource(Templates, '/template')
api.add_resource(Template, '/template/<template_id>')


if __name__ == "__main__":
    # App level secret key
    app.secret_key = "\x00\xfb\xdfB\xbf\xcd\x7f|X\xcc\x81\x92U\x1c\xc7^\xe1\x99\xbb\xfd\x9b\x93\xe2\xd4"
    app.run(debug=True)