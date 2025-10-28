from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
import os
from dotenv import load_dotenv

from shared_db.db import db
from shared_db.models import Users
from .config import Config

load_dotenv()

login_manager = LoginManager()

#Setup mail:
mail = Mail()
s = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    # Set the login view
    login_manager.login_view = '/login'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(Users, int(user_id))

    # Register blueprints
    from app.views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from app.filters import register_filters
    register_filters(app)

    return app