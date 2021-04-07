from flask import Flask, jsonify, request, make_response
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin

import jwt
import uuid
import datetime
from decouple import config
from werkzeug.security import generate_password_hash, check_password_hash

origin_list = ['https://upload-image-9ff60.web.app']

app = Flask(__name__)
api = Api(app=app)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config['CORS_HEADERS'] = 'Content-Type'
app.config[
    'SECRET_KEY'] = '\xebvp\xd8\x1f\xe5\xaa\xc6\xe7\xdbQ\xd3\xf1nG \xdf\xd3\xb7\xc2/"\xcfy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'

db = SQLAlchemy(app=app)


# Creating User model
class User(db.Model):

    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class Login(Resource):
    @cross_origin(origin=origin_list, headers=[
        'Content-Type',
    ])
    def post(self):
        auth = request.get_json()

        if not auth or not auth["username"] or not auth["password"]:
            return make_response(
                'Could not verify', 401,
                {'WWW-Authenticate': 'Basic realm="Login required!"'})

        user = User.query.filter_by(username=auth["username"]).first()

        if not user:
            return make_response(
                'Could not verify', 401,
                {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if check_password_hash(user.password, auth["password"]):
            token = jwt.encode(
                {
                    'username':
                    auth["username"],
                    'public_id':
                    user.public_id,
                    'exp':
                    datetime.datetime.utcnow() +
                    datetime.timedelta(minutes=1440),
                }, app.config['SECRET_KEY'])
            return jsonify({'token': token})

        return make_response(
            'Could not verify!', 401,
            {'WWW-Authenticate': 'Basic realm = "Login Required"'})


class Register(Resource):
    @cross_origin(origin=origin_list, headers=[
        'Content-Type',
    ])
    def post(self):
        data = request.get_json()

        hashed_password = generate_password_hash(data['password'],
                                                 method='sha256')
        new_user = User(public_id=str(uuid.uuid4()),
                        username=data['username'],
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': f'New user created - {data["username"]}'})


api.add_resource(Login, "/login")
api.add_resource(Register, "/register")