from dataclasses import dataclass
from flask import Flask, json, request, jsonify
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

import os
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER")

db = SQLAlchemy(app)
jwt = JWTManager(app)


@dataclass
class User(db.Model):
    id: int
    email: str

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password)


@dataclass
class Files(db.Model):
    id: int
    name: str
    size: int
    path: str
    score: int
    user_id: int

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    size = db.Column(db.Integer, nullable=False)
    path = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, nullable=False)


api = Api(app)


class UserController(Resource):
    def post(self):
        try:
            body = request.get_json()
            user = User(**body)
            user.hash_password()
            db.session.add(user)
            db.session.commit()
            return jsonify(user)
        except ValueError:
            print(ValueError)
            return {"msg": "Error"}

    @jwt_required
    def get(self):
        list = User.query.all()
        return jsonify(list)


class AuthController(Resource):
    def post(self):
        try:
            body = request.get_json()
            user = User.query.filter_by(email=body.get('email')).first()
            authorized = user.check_password(body.get('password'))
            if not authorized:
                return {"msg": "Email or password is invalid"}, 401
            expires = datetime.timedelta(minutes=15)
            access_token = create_access_token(
                identity=str(user.id), expires_delta=expires)
            return {"token": access_token}
        except ValueError:
            return {"msg": "Login failed, check your credential"}


class FileController(Resource):
    @jwt_required
    def get(self):
        try:
            userId = get_jwt_identity()
            files = Files.query.filter_by(user_id=userId).all()
            print(files)
            return jsonify(files)
        except ValueError:
            return {"msg": "Fail in fetchin file"}

    @jwt_required
    def post(self):
        try:
            userId = get_jwt_identity()
            file = request.files['file']
            blob = file.read()
            if(file):
                filename = secure_filename(file.filename)
                size = len(blob)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                fileData = {
                    "name": filename,
                    "size": size,
                    "path": path,
                    "user_id": userId
                }
                save = Files(**fileData)
                db.session.add(save)
                db.session.commit()
                return jsonify(save)
            else:
                return {"msg": "file not found"}
        except ValueError:
            return {"msg": "Fail in fetchin file"}


api.add_resource(UserController, "/api/v1/users")
api.add_resource(AuthController, "/api/v1/login")
api.add_resource(FileController, "/api/v1/files")

if __name__ == "__main__":
    app.run(debug=True, port=8989)
