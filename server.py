from flask import Flask, request, jsonify
from pymongo import MongoClient
import hashlib
from flask import json as payload
import google.generativeai as genai
from datetime import datetime
import os

app = Flask(__name__)
# MongoDB connection
MONGO_URI = (
    "mongodb://23521785:1234@cluster0-shard-00-00.c4bjz.mongodb.net/"
    "ltm?replicaSet=atlas-jnjp56-shard-0&ssl=true&authSource=admin"
)
client = MongoClient(MONGO_URI)
users_collection = client.ltm.users

# Configure Gemini API
genai.configure(api_key="AIzaSyCDxvUoERwsaOMeYIwtLFjgLT2TLs5iAZw")

# Utility: hash data for tokens and errors
def hash_data(data):
    if isinstance(data, (dict, list)):
        data = payload.dumps(data, sort_keys=True)
    elif not isinstance(data, str):
        data = str(data)
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify(error="Username and password are required"), 400

    if users_collection.find_one({"username": username}):
        return jsonify(error="Username already exists"), 400

    # Hash password before storing
    pwd_hash = hash_data(password)
    users_collection.insert_one({
        "username": username,
        "password": pwd_hash,
        "point": 0,
        "history": {"content": [], "created_day": []},
        "note": {"content": [], "created_day": []},
        "role": "user"
    })
    return jsonify(message="User registered successfully"), 201

# Login route
def verify_password(stored_hash, password):
    return stored_hash == hash_data(password)

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify(error="Username and password are required"), 400

    user = users_collection.find_one({"username": username})
    if not user or not verify_password(user['password'], password):
        return jsonify(error="Invalid username or password"), 401

    token = hash_data(str(user['_id']))
    return jsonify(message="Login successful", token=token), 200

# Helper: get user by token
def get_user_by_token(token):
    for user in users_collection.find():
        if hash_data(str(user['_id'])) == token:
            return user
    return None

# View ranking
@app.route('/ranking', methods=['POST'])
def ranking():
    data = request.json or {}
    token = data.get('token')
    top_users = list(users_collection.find().sort("point", -1).limit(5))
    top_list = [{"username": u['username'], "point": u['point']} for u in top_users]

    user_rank = None
    if token:
        user = get_user_by_token(token)
        if user:
            user_rank = {"username": user['username'], "point": user['point']}
    return jsonify(top_users=top_list, user_rank=user_rank), 200

# User info
@app.route('/user_info', methods=['POST'])
def user_info():
    data = request.json or {}
    token = data.get('token')
    if not token:
        return jsonify(error="User not logged in"), 401

    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404

    info = {
        "username": user['username'],
        "point": user['point'],
        "role": user['role'],
        "history": user.get('history', {}),
        "note": user.get('note', {})
    }
    return jsonify(info), 200

# Translate endpoint
@app.route('/translate', methods=['POST'])
def translate():
    data = request.json or {}
    text = data.get('text')
    from_lang = data.get('from_lang', 'auto')
    to_lang = data.get('to_lang', 'vi')
    if not text:
        return jsonify(error="Text is required"), 400

    try:   
        prompt = (
            f"Translate text from {from_lang} to {to_lang}. "
            "If the input is a single English word: translate it, include its IPA transcription, its meanings "
            "(as adjective, noun, verb, adverb), and the Vietnamese definition. "
            "If the input is an English sentence: provide the Vietnamese translation and three alternative Vietnamese renderings. "
            "Return only the translation without any additional commentary. The input text is: " + text
        )
        model = genai.GenerativeModel("gemini-2.0-flash")
        resp = model.generate_content(prompt)
        return jsonify(translated_text=resp.text.strip()), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

# Generate quiz
@app.route('/generate_quiz', methods=['POST'])
def generate_quiz():
    data = request.json or {}
    difficulty = data.get('difficulty', 'A1')
    levels = ['A1','A2','B1','B2','C1','C2']
    if difficulty not in levels:
        return jsonify(error="Invalid difficulty level"), 400

    prompt = (
            f"Create a {difficulty}-level English quiz with 4 multiple-choice questions. "
            "For each question: provide the question text, four options labeled A–D, and indicate the correct answer. "
        )
    model = genai.GenerativeModel("gemini-2.0-flash")
    resp = model.generate_content(prompt)
    return jsonify(quiz=resp.text.strip()), 200

# History & Note helpers
def current_day():
    return datetime.now().date().isoformat()

@app.route('/add_history', methods=['POST'])
def add_history():
    data = request.json or {}
    token, content = data.get('token'), data.get('content')
    if not token or not content:
        return jsonify(error="Token and content are required"), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    users_collection.update_one(
        {"_id": user['_id']},
        {"$push": {"history.content": content, "history.created_day": current_day()}}
    )
    return jsonify(message="History added"), 200

@app.route('/view_history', methods=['POST'])
def view_history():
    token = request.json.get('token')
    if not token:
        return jsonify(error="Token is required"), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    hist = user.get('history', {})
    return jsonify(content=hist.get('content', []), created_day=hist.get('created_day', [])), 200

# Similarly for notes
@app.route('/add_note', methods=['POST'])
def add_note():
    data = request.json or {}
    token, content = data.get('token'), data.get('content')
    if not token or not content:
        return jsonify(error="Token and content are required"), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    users_collection.update_one(
        {"_id": user['_id']},
        {"$push": {"note.content": content, "note.created_day": current_day()}}
    )
    return jsonify(message="Note added"), 200

@app.route('/view_note', methods=['POST'])
def view_note():
    token = request.json.get('token')
    if not token:
        return jsonify(error="Token is required"), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    note = user.get('note', {})
    return jsonify(content=note.get('content', []), created_day=note.get('created_day', [])), 200

# Admin: list users
@app.route('/admin/users', methods=['GET'])
def get_all_users():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify(error="Authorization token is required"), 401
    admin = get_user_by_token(token)
    if not admin or admin['role'] != 'admin':
        return jsonify(error="Unauthorized access"), 403
    users = []
    for u in users_collection.find({}, {"password":0}):
        users.append({
            "username": u['username'],
            "point": u['point'],
            "role": u['role']
        })
    return jsonify(users), 200

if __name__ == "__main__":
    # Pick up PORT from env, default to 5000
    port = int(os.environ.get("PORT", 5000))
    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        resp = model.generate_content("Test connection")
        print("Gemini API connected successfully.")
    except Exception as e:
        print(f"Error connecting to Gemini API: {e}")
    # Run on all interfaces so the load-balancer can reach it
    app.run(host="0.0.0.0", port=port, debug=True)

