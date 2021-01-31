from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

import os
import datetime

from databases.db import db
from databases.models import User, Files
from resources.UserController import UserController
from resources.FileController import FileController
from resources.AuthController import AuthController

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER")

jwt = JWTManager(app)


db.init_app(app)

api = Api(app)

api.add_resource(UserController, "/api/v1/users")
api.add_resource(AuthController, "/api/v1/login")
api.add_resource(FileController, "/api/v1/files")

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
