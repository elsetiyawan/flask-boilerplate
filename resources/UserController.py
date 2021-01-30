
from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import jwt_required

from app import db, User


class UserC(Resource):
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
