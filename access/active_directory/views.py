import json
from app import app
from app import db
from access.active_directory.models import ActiveDirectory
from flask import jsonify
from flask import request
from sqlalchemy.exc import SQLAlchemyError
from utils import decrypt_jwt
from access.user.models import User
from flask_utils.api import ApiView
api = ApiView(class_instance=ActiveDirectory, identifier_attr='id', relationships=[], db=db)

@app.route('/auth/active_directory', methods=['POST', 'GET', 'PUT', 'DELETE'])
def ad():
    token = decrypt_jwt(request.headers.get('Authorization', None))
    if token is not None:
        user = User.query.get(token.get('user_email', None))
        if user is not None:
            if request.method == 'GET':
                return api.get(identifier_value=request.args.get('identifier', None))
            elif request.method == 'POST':
                return api.post(request)
            elif request.method == 'PUT':
                return api.put(request, identifier_value=request.json.get('identifier', None))
            elif request.method == 'DELETE':
                return api.delete(db=db, identifier_value=request.json.get('identifier', None))
        else:
            return jsonify({'status': 'error', 'description': 'unauthorized', 'code': 401}), 401
    else:
        return jsonify({'status': 'error', 'description': 'unauthorized', 'code': 401}), 401

@app.route('/auth/list/active_directory', methods=['GET'])
def list_ad():
    token = decrypt_jwt(request.headers.get('Authorization', None))
    if token is not None:
        user = User.query.get(token.get('user_email', None))
        if user is not None:
            return api.list(request, db)
        else:
            return jsonify({'status': 'error', 'description': 'unauthorized', 'code': 401}), 401
    else:
        return jsonify({'status': 'error', 'description': 'unauthorized', 'code': 401}), 401
