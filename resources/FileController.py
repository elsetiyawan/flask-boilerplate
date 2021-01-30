from flask import request, jsonify, current_app
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import os

from databases.db import db
from databases.models import Files


class FileController(Resource):
    @jwt_required
    def get(self):
        try:
            userId = get_jwt_identity()
            files = Files.query.filter_by(user_id=userId).all()
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
                path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
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
