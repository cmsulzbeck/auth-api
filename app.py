from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

import jwt
import datetime

# TODO modularizar a aplicação

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_api.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(60), nullable=False)
    date_craeted = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    print(f"Entering {username} and password {password}")

    user = User.query.filter_by(username=username).first()
    print(f"User found: {user.username} and password {user.password}")

    # TODO implementar hashing de senha
    if not user or user.password != password:
        return jsonify({'message': "Invalid credentials"}), 401
    
    # TODO implementar codificação de JWT
    # token = jwt.JWT.encode({
    #     'sub': user.id,
    #     'iat': datetime.datetime.utcnow(),
    #     'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    # }, 'my-secret-key')    
# token = jwt.encode({
    #     'sub': user.id,
    #     'iat': datetime.datetime.utcnow(),
    #     'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    # }, 'my-secret-key')

    return jsonify({'message': 'User authenticated!'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'message': 'Missing data'}), 400
    
    new_user = User(username=username, email=email, password=password)

    try:
        db.session.add(new_user)
        db.session.commit()
        print(f"Saving user {username} and password {password}")
        return jsonify({'message': 'User created successfully'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Unable to create user'}), 500
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)