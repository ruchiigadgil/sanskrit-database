from flask import Flask, request, jsonify
from flask_cors import CORS
from db import get_db_connection
import jwt
from datetime import datetime, timedelta, timezone
from bson.json_util import dumps
from bson.objectid import ObjectId
import bcrypt
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {
    "origins": ["http://localhost:5173"],
    "methods": ["GET", "POST", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

# === JWT Configuration ===
JWT_SECRET_KEY = 'sanskrit-learning-system-secret-key-2024'
JWT_ALGORITHM = 'HS256'

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
    data = request.json
    full_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({'message': 'Full name, email, and password are required'}), 400

    try:
        db = get_db_connection()
        if db.users.find_one({"email": email}):
            return jsonify({'message': 'Email already registered'}), 409
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        result = db.users.insert_one({
            "full_name": full_name,
            "email": email,
            "password": hashed_password,
            "score": 0
        })
        user = db.users.find_one({"_id": result.inserted_id})
        user_dict = {
            'id': str(user['_id']),
            'fullName': user['full_name'],
            'email': user['email'],
            'score': user['score']
        }
        token = jwt.encode({
            'user_id': str(user['_id']),
            'email': user['email'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        logger.info(f"Registered user: {email}")
        return jsonify({
            'message': 'User registered successfully!',
            'user': user_dict,
            'token': token
        }), 201
    except Exception as e:
        logger.error(f"Error in register: {str(e)}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    try:
        db = get_db_connection()
        user = db.users.find_one({"email": email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            token = jwt.encode({
                'user_id': str(user['_id']),
                'email': user['email'],
                'exp': datetime.now(timezone.utc) + timedelta(hours=24)
            }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            user_dict = {
                'id': str(user['_id']),
                'full_name': user['full_name'],
                'email': user['email'],
                'score': user['score']
            }
            logger.info(f"User logged in: {email}")
            return jsonify({
                'message': 'Login successful!',
                'user': user_dict,
                'token': token
            }), 200
        else:
            return jsonify({'message': 'Invalid email or password'}), 401
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/api/profile', methods=['GET', 'OPTIONS'])
def get_profile():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
        response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Authorization header required'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        db = get_db_connection()
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            user_dict = {
                'id': str(user['_id']),
                'full_name': user['full_name'],
                'email': user['email'],
                'score': user['score']
            }
            logger.info(f"Profile fetched for user: {user['email']}")
            return jsonify(user_dict), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Error in get_profile: {str(e)}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/api/update-score', methods=['POST', 'OPTIONS'])
def update_score():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Authorization header required'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        data = request.json
        score_increment = data.get('score')
        if not user_id or score_increment is None:
            return jsonify({'message': 'Missing userId or score'}), 400
        db = get_db_connection()
        result = db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$inc": {"score": score_increment}}
        )
        if result.matched_count == 0:
            return jsonify({'message': 'User not found'}), 404
        user = db.users.find_one({"_id": ObjectId(user_id)})
        logger.info(f"Score updated for {user['email']}: {user['score']}")
        return jsonify({
            'message': 'Score updated successfully!',
            'score': user['score']
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Error in update_score: {str(e)}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/api/save-score', methods=['POST', 'OPTIONS'])
def save_score():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Authorization header required'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        data = request.json
        score = data.get('score')
        if not user_id or score is None:
            return jsonify({'message': 'Missing user_id or score'}), 400
        db = get_db_connection()
        result = db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"score": score}}
        )
        if result.matched_count == 0:
            return jsonify({'message': 'User not found'}), 404
        user = db.users.find_one({"_id": ObjectId(user_id)})
        logger.info(f"Score saved for {user['email']}: {user['score']}")
        return jsonify({
            'message': 'Score saved successfully!',
            'score': user['score']
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Error in save_score: {str(e)}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/api/test', methods=['GET'])
def test():
    try:
        db = get_db_connection()
        users = list(db.users.find())
        users_dict = [{
            'id': str(user['_id']),
            'full_name': user['full_name'],
            'email': user['email'],
            'score': user['score']
        } for user in users]
        logger.info("Test endpoint accessed")
        return jsonify({
            'message': 'Connection successful!',
            'users': users_dict
        }), 200
    except Exception as e:
        logger.error(f"Error in test: {str(e)}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health():
    try:
        db = get_db_connection()
        db.command('ping')
        logger.info("Health check successful")
        return jsonify({"status": "healthy", "server": "database"}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5006, debug=True)