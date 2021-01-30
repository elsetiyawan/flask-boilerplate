from dataclasses import dataclass
from flask_bcrypt import generate_password_hash, check_password_hash

from .db import db


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
