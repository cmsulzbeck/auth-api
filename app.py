from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone

import jwt
import bcrypt
import io, os, sys, config

# TODO modularizar a aplicação

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_api.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(60), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    session_token = db.Column(db.String(255), unique=True, default=None)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.session_token}')"
    
cfg = config.ConfigError('config.cfg')

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # print(f"Entering {username} and password {password}")

    user = User.query.filter_by(username=username).first()
    # print(f"User found: {user.username} and password {user.password}")
    # hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # print(f"Hashed Password: {hashed_password}")

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password):
        return jsonify({'message': "Invalid credentials"}), 401
    
    message = {
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1),
        'data': {'user_id': user.id, 'username': user.username}
    }
    signing_key = cfg['secret_key']
    token = jwt.encode(message, signing_key.encode('utf-8'), algorithm='HS256')
    
    user.session_token = token
    db.session.add(user)
    db.session.commit()

    return jsonify({'token': token})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    if not all([username, email, password]):
        return jsonify({'message': 'Missing data'}), 400
    
    new_user = User(username=username, email=email, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        print(f"Saving user {username} and password {hashed_password}")
        return jsonify({'message': 'User created successfully'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Unable to create user'}), 500

@app.route('/logoff', methods=['POST'])
def logoff():
    session_token = request.headers.get('Authorization')
    if not session_token:
        return jsonify({'message': 'No session_token provided'}), 400
    
    user = User.query.filter_by(session_token=session_token).first()

    user.session_token = None
    db.session.commit()

    return jsonify({'message': 'Logged off successfully'}), 200

@app.route('/users', methods=['GET'])
def getUsers():
    users = User.query.filter_by().all()
    print(f"Users found: f{users}")

    return jsonify({'message': 'Retrieved Users information!'})
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)