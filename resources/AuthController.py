from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from databases.db import db
from databases.models import User

import datetime


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
