from flask import Flask
from flask_migrate import Migrate
from flask_restx import Api
from flask_jwt_extended import JWTManager

from config import DevConfig
from models import Recipe, User
from exts import db
from API import auth, recipes

def create_app(config):
    app = Flask(__name__)
    app.config.from_object(config)
    api = Api(app, doc='/docs')
    db.init_app(app)
    migrate = Migrate(app, db)
    api.add_namespace(auth.auth_ns)
    api.add_namespace(recipes.recipe_ns)


    @app.shell_context_processor
    def make_shell_context():
        return {
            'db': db,
            'Recipe': Recipe,
            'user': User
        }


    return app
