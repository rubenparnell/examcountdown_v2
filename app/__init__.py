from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer

from app.config import Config

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

#Setup mail:
mail = Mail()
s = URLSafeTimedSerializer(Config.SECRET_KEY)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)

    # Set the login view
    login_manager.login_view = '/login'

    # Register blueprints
    from app.views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app

# Import the Users model
from app.models import Users

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))
