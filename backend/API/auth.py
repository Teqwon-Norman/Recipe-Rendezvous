from flask_restx import Namespace, Resource, fields
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required

from models import User

auth_ns = Namespace('auth', description='A namespace for our authentication')

signup_model = auth_ns.model(
    'SignUp',
    {
        'username': fields.String(),
        'email': fields.String(),
        'password': fields.String()
    }
)

login_model = auth_ns.model(
    'Login',
    {
        'username': fields.String(),
        'password': fields.String()
    }
)

@auth_ns.route('/signup')
@auth_ns.expect(signup_model)
class SignUp(Resource):
    @auth_ns.marshal_list_with(signup_model)
    def get(self):
        """ Get all users """
        data = User.query.all()
        return data

    def post(self):
        """ Create a new user """
        data = request.get_json()

        # check if username exists in database already
        username = data.get('username')
        db_user = User.query.filter_by(username=username).first()
        if db_user: return jsonify({'message' : f'User with username {username} already exists!!'})

        new_user = User(
            username = data.get('username'),
            email = data.get('email'),
            password = generate_password_hash(data.get('password'), 'sha256')
        )

        new_user.save()
        return jsonify({'message' : 'User created successfully!'})
    
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        db_user = User.query.filter_by(username=username).first()
        if db_user and check_password_hash(db_user.password, password):
            access_token = create_access_token(identity=db_user.username)
            refresh_token = create_refresh_token(identity=db_user.username)
            return jsonify(
                {
                    'access token' : access_token,
                    'refresh token' : refresh_token
                }
            )
        return jsonify({'message' : 'User does not exist!'}) 