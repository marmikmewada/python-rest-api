import logging
import jwt
import datetime
from flask import Flask, request, jsonify
from pymongo import MongoClient
import os
# Configure logging
logging.basicConfig(level=logging.INFO)  # Set to INFO to reduce log verbosity
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') # Change this to a secure random key

# Connect to MongoDB
try:
    client = MongoClient(os.getenv('MONGODB_URI'))
    mongodb = client.test  # Use your database name here
    logger.info("MongoDB initialized.")
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")

# Helper function to verify JWT tokens
def token_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = mongodb.users.find_one({"username": data['username']})
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(current_user, *args, **kwargs)

    wrapper.__name__ = f.__name__  # Ensure the wrapper function has the same name as the original function
    return wrapper

@app.route("/")
def hello():
    return "This app is working"

@app.route("/api/signup", methods=['POST'])
def signup():
    data = request.get_json()
    user_data = {
        'username': data['username'],
        'email': data['email'],
        'password': data['password']  # No hashing for passwords
    }
    mongodb.users.insert_one(user_data)
    logger.info("User created successfully.")
    return jsonify({'message': 'User created'}), 201

@app.route("/api/login", methods=['POST'])
def login():
    data = request.get_json()
    user = mongodb.users.find_one({"username": data['username']})

    if user and user['password'] == data['password']:  # No hashing for passwords
        token = jwt.encode({
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=27)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route("/api/todo", methods=['GET', 'POST'])
@token_required
def todo_route(current_user):
    if request.method == 'POST':
        data = request.get_json()
        todo_data = {
            'title': data['title'],
            'completed': data.get('completed', False)
        }
        mongodb.todos.insert_one(todo_data)
        logger.info("Todo created successfully.")
        return jsonify({'message': 'Todo created'}), 201
    else:
        todos = list(mongodb.todos.find())
        return jsonify({"todos": todos}), 200

@app.route("/api/users", methods=['GET'])
@token_required
def user_route(current_user):
    users = list(mongodb.users.find())
    return jsonify({"users": users}), 200

if __name__ == '__main__':
    app.run(debug=True)
