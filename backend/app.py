from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_restx import Api, Resource, fields
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash

from config import DevConfig
from models import Recipe, User
from exts import db

app = Flask(__name__)
app.config.from_object(DevConfig)

api = Api(app, doc='/docs')

db.init_app(app)

JWTManager(app)
migrate = Migrate(app, db)


# model (serializer)
recipe_model = api.model(
    'Recipe',
    {
        'id': fields.Integer(),
        'title': fields.String(),
        'description': fields.String()
    }
)

# signup schema
signup_model = api.model(
    'SignUp',
    {
        'username': fields.String(),
        'email': fields.String(),
        'password': fields.String()
    }
)

# login schema
login_model = api.model(
    'Login',
    {
        'username': fields.String(),
        'password': fields.String()
    }
)

@api.route('/hello')
class HelloResource(Resource):
    def get(self):
        return {'message': 'Hello World'}

@api.route('/signup')
@api.expect(signup_model)
class SignUp(Resource):
    @api.marshal_list_with(signup_model)
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

@api.route('/login')
class Login(Resource):
    @api.expect(login_model)
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


@api.route('/recipes')
class RecipesResource(Resource):
    @api.marshal_list_with(recipe_model)
    def get(self):
        """Get all recipes """
        recipes = Recipe.query.all()
        return recipes

    @api.marshal_with(recipe_model)
    @api.expect(recipe_model)
    @jwt_required()
    def post(self):
        """Create a new recipe """
        data = request.get_json()

        new_recipe = Recipe(
            title=data.get('title'),
            description=data.get('description')
        )

        new_recipe.save()
        return new_recipe, 201


@api.route('/recipe/<int:id>')
class RecipeResource(Resource):
    @api.marshal_with(recipe_model)
    def get(self, id):
        """Get a recipe by id"""
        recipe = Recipe.query.get_or_404(id)
        return recipe

    @api.marshal_with(recipe_model)
    @jwt_required()
    def put(self, id): 
        """Update a recipe by id"""
        recipe_to_update = Recipe.query.get_or_404(id)
        data = request.get_json()
        recipe_to_update.update(data.get('title'), data.get('description'))
        return recipe_to_update

    @api.marshal_with(recipe_model)
    @jwt_required()
    def delete(self, id):
        """Delete a recipe by id"""
        recipe_to_delete = Recipe.query.get_or_404(id)
        recipe_to_delete.delete()
        return recipe_to_delete, 204


@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'Recipe': Recipe,
    }


if __name__ == '__main__':
    app.run(debug=True)
