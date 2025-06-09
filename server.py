from flask import Flask, request, jsonify
from pymongo import MongoClient
import hashlib
import google.generativeai as genai
from datetime import datetime
import os
import json

app = Flask(__name__)

MONGO_URI = (
    "mongodb://23521785:1234@cluster0-shard-00-00.c4bjz.mongodb.net/"
    "ltm?replicaSet=atlas-jnjp56-shard-0&ssl=true&authSource=admin"
)
client = MongoClient(MONGO_URI)
db = client.ltm
users_collection = db.users

genai.configure(api_key="AIzaSyCDxvUoERwsaOMeYIwtLFjgLT2TLs5iAZw")

def hash_data(data_str):
    return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

def get_user_by_token(token):
    if not token: return None
    user_token_hash = hash_data(token)
    return users_collection.find_one({"token_hash": user_token_hash})

def ensure_history_array(user_id):
    user = users_collection.find_one({"_id": user_id})
    if not isinstance(user.get('history'), list):
        users_collection.update_one(
            {"_id": user_id},
            {"$set": {"history": []}}
        )

def add_to_history(user_id, type, input_text, output_data):
    ensure_history_array(user_id)
    users_collection.update_one(
        {"_id": user_id},
        {"$push": {
            "history": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": type,
                "input": input_text,
                "output": output_data
            }
        }}
    )

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify(error="Username and password are required"), 400
    if users_collection.find_one({"username": username}):
        return jsonify(error="Username already exists"), 400

    password_hash = hash_data(password)
    users_collection.insert_one({
        "username": username,
        "password": password_hash,
        "role": "user",
        "point": 0,
        "history": [],
        "note": {"content": [], "created_day": []},
        "token_hash": None
    })
    return jsonify(message="User registered successfully"), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = users_collection.find_one({"username": username})
    if user and user['password'] == hash_data(password):
        token = f"{username}:{datetime.now()}"
        token_hash = hash_data(token)
        users_collection.update_one({"_id": user['_id']}, {"$set": {"token_hash": token_hash}})
        return jsonify(token=token), 200
    return jsonify(error="Invalid credentials"), 401

@app.route('/translate', methods=['POST'])
def translate():
    data = request.json
    token = data.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="Invalid or missing token"), 401
    
    text = data.get('text')
    from_lang = data.get('from_lang', 'auto')
    to_lang = data.get('to_lang', 'vi')
    if not text:
        return jsonify(error="Text is required"), 400
    
    try:
        prompt_template = """
            You are a translation assistant.

            You will be given:
            - An input text in '{from_lang}'.
            - Your task is to translate it into '{to_lang}'.
            - Then return a JSON response with the following structure:

            {{
            "original_language": "string",
            "original_text": "string",
            "target_language": "string",
            "translated_text": "string",
            "phonetic": "string (optional)",
            "meanings": [
                {{
                "part_of_speech": "string",
                "definition": "string"
                }}
            ],
            "alternatives": ["string"]
            }}

            Guidelines:
            - JSON only, no markdown, no explanations.
            - Phonetic must match the **original text** in the **original language**.
            - The "alternatives" field must contain other ways to say the same thing in the **original language** (NOT translations).
            - Keys and structure must match exactly.
            - No extra text before or after the JSON.

            Now translate this:

            "{text}"
            """

        prompt = prompt_template.format(
            from_lang=from_lang,
            to_lang=to_lang,
            text=text.replace('"', '\\"')
        )
        model = genai.GenerativeModel("gemini-2.0-flash")
        resp = model.generate_content(prompt)

        cleaned_response = resp.text
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:]
        if cleaned_response.endswith('```'):
            cleaned_response = cleaned_response[:-3]
        
        translated_data = json.loads(cleaned_response.strip())

        add_to_history(user['_id'], 'translate', text, translated_data)
        
        return jsonify(translated_text=translated_data), 200
    except json.JSONDecodeError as e:
        app.logger.error(f"JSON Decode Error: {e} - Response text: {cleaned_response}")
        return jsonify(error=f"Failed to parse AI response: {str(e)}"), 500
    except Exception as e:
        app.logger.error(f"Translation Error: {e}")
        return jsonify(error=str(e)), 500

@app.route('/translate_without_auth', methods=['POST'])
def translate_without_auth():
    data = request.json
    text = data.get('text')
    from_lang = data.get('from_lang', 'auto')
    to_lang = data.get('to_lang', 'vi')
    if not text:
        return jsonify(error="Text is required"), 400
    
    try:
        prompt_template = """
            You are a translation assistant.

            You will be given:
            - An input text in '{from_lang}'.
            - Your task is to translate it into '{to_lang}'.
            - Then return a JSON response with the following structure:

            {{
            "original_language": "string",
            "original_text": "string",
            "target_language": "string",
            "translated_text": "string",
            "phonetic": "string (optional)",
            "meanings": [
                {{
                "part_of_speech": "string",
                "definition": "string"
                }}
            ],
            "alternatives": ["string"]
            }}

            Guidelines:
            - JSON only, no markdown, no explanations.
            - Phonetic must match the **original text** in the **original language**.
            - The "alternatives" field must contain other ways to say the same thing in the **original language** (NOT translations).
            - Keys and structure must match exactly.
            - No extra text before or after the JSON.

            Now translate this:

            "{text}"
            """

        prompt = prompt_template.format(
            from_lang=from_lang,
            to_lang=to_lang,
            text=text.replace('"', '\\"')
        )
        model = genai.GenerativeModel("gemini-2.0-flash")
        resp = model.generate_content(prompt)

        cleaned_response = resp.text
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:]
        if cleaned_response.endswith('```'):
            cleaned_response = cleaned_response[:-3]
        
        translated_data = json.loads(cleaned_response.strip())
        
        return jsonify(translated_text=translated_data), 200
    except json.JSONDecodeError as e:
        app.logger.error(f"JSON Decode Error: {e} - Response text: {cleaned_response}")
        return jsonify(error=f"Failed to parse AI response: {str(e)}"), 500
    except Exception as e:
        app.logger.error(f"Translation Error: {e}")
        return jsonify(error=str(e)), 500
    

@app.route('/generate_quiz', methods=['POST'])
def generate_quiz():
    data = request.json
    token = data.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="Invalid or missing token"), 401

    difficulty = data.get('difficulty', 'A1')
    
    prompt = f"""
    Create a {difficulty}-level English quiz with 4 multiple-choice questions.

    Requirements:
    - All questions must be based on plain text only.
    - Do NOT include any questions that refer to images, diagrams, videos, or audio.
    - Each question must be answerable by reading the question and options only.
    - Your response MUST be a valid JSON object and nothing else.
    - Do NOT include any markdown formatting (like ```json).
    - Do NOT add any explanation before or after the JSON.

    The JSON object must have a single root key "questions", which is an array of 4 question objects.
    Each question object must have these exact keys:
    - "question": string
    - "options": array of 4 strings
    - "answer": one of the 4 options (string)
    """
    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        resp = model.generate_content(prompt)
        cleaned_response = resp.text
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:]
        if cleaned_response.endswith('```'):
            cleaned_response = cleaned_response[:-3]
        
        quiz_data = json.loads(cleaned_response.strip())
        
        add_to_history(user['_id'], 'quiz', f"Generated a {difficulty} quiz", f"{len(quiz_data.get('questions',[]))} questions")
        
        return jsonify(quiz_data), 200
    except json.JSONDecodeError as e:
        app.logger.error(f"JSON Decode Error: {e} - Response text: {cleaned_response}")
        return jsonify(error=f"Failed to parse AI response: {str(e)}"), 500
    except Exception as e:
        app.logger.error(f"Quiz Generation Error: {e}")
        return jsonify(error=f"Failed to generate or parse quiz from AI response: {str(e)}"), 500


@app.route('/view_history', methods=['POST'])
def view_history():
    token = request.json.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404

    history_list = []
    for item in user.get('history', []):
        output_display = item.get('output', '')
        if isinstance(output_display, dict):
            output_display = output_display.get('translated_text', json.dumps(output_display))
        history_list.append({
            "timestamp": item.get('timestamp', ''),
            "type": item.get('type', ''),
            "input": item.get('input', ''),
            "output": output_display
        })
    return jsonify(history=history_list), 200

@app.route('/save_note', methods=['POST'])
def save_note():
    token = request.json.get('token')
    content = request.json.get('content')
    if not content:
        return jsonify(error="Content is required"), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    
    users_collection.update_one(
        {"_id": user['_id']},
        {"$push": {
            "note.content": content,
            "note.created_day": datetime.now().strftime("%Y-%m-%d")
        }}
    )
    return jsonify(message="Note saved"), 200

@app.route('/view_note', methods=['POST'])
def view_note():
    token = request.json.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    note = user.get('note', {})
    return jsonify(content=note.get('content', []), created_day=note.get('created_day', [])), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)