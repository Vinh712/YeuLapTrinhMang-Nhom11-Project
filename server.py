from flask import Flask, request, jsonify
from pymongo import MongoClient
import google.generativeai as genai
from datetime import datetime
import os
import json
import hashlib

# --- aes_crypto.py content start ---
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class AESCrypto:
    def __init__(self, key=None):
        if key is None:
            self.key = get_random_bytes(32)
        else:
            if isinstance(key, str):
                key = key.encode("utf-8")
            if len(key) < 32:
                key = key + b'0' * (32 - len(key))
            elif len(key) > 32:
                key = key[:32]
            self.key = key
    
    def encrypt(self, data):
        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data, ensure_ascii=False)
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        padded_data = pad(data, AES.block_size)
        
        encrypted_data = cipher.encrypt(padded_data)
        
        result = base64.b64encode(iv + encrypted_data).decode("utf-8")
        return result
    
    def decrypt(self, encrypted_data):
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode("utf-8"))
            
            iv = encrypted_bytes[:16]
            encrypted_content = encrypted_bytes[16:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_content)
            
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            result = decrypted_data.decode("utf-8")
            
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return result
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def get_key_base64(self):
        return base64.b64encode(self.key).decode("utf-8")
    
    @classmethod
    def from_key_base64(cls, key_base64):
        key = base64.b64decode(key_base64.encode("utf-8"))
        return cls(key)

def create_user_crypto(user_id):
    key_material = f"user_crypto_{user_id}".encode("utf-8")
    key = hashlib.sha256(key_material).digest()
    return AESCrypto(key)

def encrypt_user_data(user_id, data):
    crypto = create_user_crypto(user_id)
    return crypto.encrypt(data)

def decrypt_user_data(user_id, encrypted_data):
    crypto = create_user_crypto(user_id)
    return crypto.decrypt(encrypted_data)
# --- aes_crypto.py content end ---

# --- basic_translator.py content start ---
import re

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False
        self.word_data = None

class Trie:
    def __init__(self):
        self.root = TrieNode()
    
    def insert(self, word, word_data):
        node = self.root
        for char in word.lower():
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        
        node.is_end_of_word = True
        node.word_data = word_data
    
    def search(self, word):
        node = self.root
        for char in word.lower():
            if char not in node.children:
                return None
            node = node.children[char]
        
        if node.is_end_of_word:
            return node.word_data
        return None
    
    def starts_with(self, prefix):
        node = self.root
        for char in prefix.lower():
            if char not in node.children:
                return []
            node = node.children[char]
        
        results = []
        self._collect_words(node, prefix.lower(), results)
        return results
    
    def _collect_words(self, node, prefix, results):
        if node.is_end_of_word:
            results.append({
                'word': prefix,
                'data': node.word_data
            })
        
        for char, child_node in node.children.items():
            self._collect_words(child_node, prefix + char, results)

class BasicTranslator:
    def __init__(self, dictionary_data):
        self.trie = Trie()
        self.word_dict = {}
        
        for word_entry in dictionary_data:
            word = word_entry['word']
            self.trie.insert(word, word_entry)
            self.word_dict[word.lower()] = word_entry
    
    def translate_word(self, word):
        result = self.trie.search(word)
        if result:
            return self._format_translation(result)
        
        word_lower = word.lower()
        if word_lower in self.word_dict:
            return self._format_translation(self.word_dict[word_lower])
        
        return None
    
    def translate_text(self, text):
        words = re.findall(r'\b\w+\b|\W+', text)
        
        translated_words = []
        found_translations = []
        
        for word in words:
            if re.match(r'\b\w+\b', word):
                translation = self.translate_word(word)
                if translation:
                    translated_words.append(translation['primary_translation'])
                    found_translations.append({
                        'original': word,
                        'translation': translation
                    })
                else:
                    translated_words.append(word)
            else:
                translated_words.append(word)
        
        return {
            'original_text': text,
            'translated_text': ''.join(translated_words),
            'word_translations': found_translations,
            'translation_type': 'basic'
        }
    
    def _format_translation(self, word_data):
        primary_translation = ""
        all_translations = []
        
        for meaning in word_data.get('meanings', []):
            for definition in meaning.get('definitions', []):
                translation = definition.get('translation', '')
                if translation:
                    if not primary_translation:
                        primary_translation = translation
                    all_translations.append({
                        'part_of_speech': meaning.get('part_of_speech', ''),
                        'definition': definition.get('definition', ''),
                        'translation': translation,
                        'example': definition.get('example', '')
                    })
        
        return {
            'word': word_data['word'],
            'phonetic': word_data.get('phonetic', ''),
            'primary_translation': primary_translation,
            'all_translations': all_translations
        }
    
    def suggest_words(self, prefix):
        suggestions = self.trie.starts_with(prefix)
        return [s['word'] for s in suggestions[:10]]
# --- basic_translator.py content end ---

# --- quiz_manager.py content start ---
class QuizManager:
    def __init__(self):
        self.difficulty_points = {
            'A1': 5,
            'A2': 7,
            'B1': 10,
            'B2': 12,
            'C1': 15,
            'C2': 20
        }
    
    def calculate_score(self, difficulty, correct_answers, total_questions):
        if total_questions == 0:
            return 0
        
        base_points = self.difficulty_points.get(difficulty, 5)
        score = (correct_answers / total_questions) * base_points
        return int(score)
    
    def evaluate_quiz(self, quiz_data, user_answers):
        questions = quiz_data.get('questions', [])
        total_questions = len(questions)
        correct_answers = []
        incorrect_answers = []
        
        for i, question in enumerate(questions):
            correct_answer = question.get('answer', '')
            user_answer = user_answers.get(str(i), '')
            
            question_result = {
                'question': question.get('question', ''),
                'options': question.get('options', []),
                'correct_answer': correct_answer,
                'user_answer': user_answer
            }
            
            if user_answer == correct_answer:
                correct_answers.append(question_result)
            else:
                incorrect_answers.append(question_result)
        
        return {
            'total_questions': total_questions,
            'correct_count': len(correct_answers),
            'incorrect_count': len(incorrect_answers),
            'correct_answers': correct_answers,
            'incorrect_answers': incorrect_answers,
            'percentage': (len(correct_answers) / total_questions * 100) if total_questions > 0 else 0
        }
    
    def format_quiz_result(self, difficulty, evaluation_result):
        score = self.calculate_score(
            difficulty, 
            evaluation_result['correct_count'], 
            evaluation_result['total_questions']
        )
        
        return {
            'type': 'quiz',
            'difficulty': difficulty,
            'score': score,
            'total_questions': evaluation_result['total_questions'],
            'correct_count': evaluation_result['correct_count'],
            'incorrect_count': evaluation_result['incorrect_count'],
            'percentage': evaluation_result['percentage'],
            'correct_answers': evaluation_result['correct_answers'],
            'incorrect_answers': evaluation_result['incorrect_answers']
        }
# --- quiz_manager.py content end ---

# --- ranking_manager.py content start ---
class RankingManager:
    def __init__(self, users_collection):
        self.users_collection = users_collection
    
    def get_top_users(self, limit=5):
        try:
            top_users = list(self.users_collection.find(
                {},
                {"username": 1, "point": 1, "_id": 0}
            ).sort("point", -1).limit(limit))
            
            for i, user in enumerate(top_users):
                user['rank'] = i + 1
            
            return top_users
        except Exception as e:
            print(f"Error getting top users: {e}")
            return []
    
    def get_user_rank(self, username):
        try:
            user = self.users_collection.find_one({"username": username}, {"point": 1})
            if not user:
                return None
            
            user_points = user.get('point', 0)
            
            higher_users = self.users_collection.count_documents({"point": {"$gt": user_points}})
            
            rank = higher_users + 1
            
            return {
                'username': username,
                'point': user_points,
                'rank': rank
            }
        except Exception as e:
            print(f"Error getting user rank: {e}")
            return None
    
    def update_user_points(self, username, points_to_add):
        try:
            result = self.users_collection.update_one(
                {"username": username},
                {"$inc": {"point": points_to_add}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating user points: {e}")
            return False
    
    def get_ranking_stats(self):
        try:
            total_users = self.users_collection.count_documents({})
            
            top_user = list(self.users_collection.find({}, {"username": 1, "point": 1, "_id": 0}).sort("point", -1).limit(1))
            
            pipeline = [
                {"$group": {"_id": None, "avg_points": {"$avg": "$point"}}}
            ]
            avg_result = list(self.users_collection.aggregate(pipeline))
            avg_points = avg_result[0]['avg_points'] if avg_result else 0
            
            return {
                'total_users': total_users,
                'top_user': top_user[0] if top_user else None,
                'average_points': round(avg_points, 2)
            }
        except Exception as e:
            print(f"Error getting ranking stats: {e}")
            return {
                'total_users': 0,
                'top_user': None,
                'average_points': 0
            }
# --- ranking_manager.py content end ---

app = Flask(__name__)

# Cấu hình MongoDB
MONGO_URI = (
    "mongodb://23521785:1234@cluster0-shard-00-00.c4bjz.mongodb.net/"
    "ltm?replicaSet=atlas-jnjp56-shard-0&ssl=true&authSource=admin"
)
client = MongoClient(MONGO_URI)
db = client.ltm
users_collection = db.users
dictionary_collection = db.dictionary

# Cấu hình Gemini AI
genai.configure(api_key="AIzaSyCDxvUoERwsaOMeYIwtLFjgLT2TLs5iAZw")

# Khởi tạo các manager
quiz_manager = QuizManager()
ranking_manager = RankingManager(users_collection)

# Load dictionary data và khởi tạo basic translator
try:
    # Tải từ điển từ MongoDB thay vì file local
    dictionary_data = list(dictionary_collection.find({}))
    if not dictionary_data:
        # Fallback: nếu MongoDB không có data, tải từ file local
        with open('/home/ubuntu/extended_dictionary.json', 'r', encoding='utf-8') as f:
            dictionary_data = json.load(f)
        print(f"Loaded dictionary from local file with {len(dictionary_data)} words")
    else:
        # Chuyển đổi ObjectId thành string để tránh lỗi serialization
        for word_entry in dictionary_data:
            if '_id' in word_entry:
                word_entry['_id'] = str(word_entry['_id'])
        print(f"Loaded dictionary from MongoDB with {len(dictionary_data)} words")
    
    basic_translator = BasicTranslator(dictionary_data)
except Exception as e:
    print(f"Warning: Could not load dictionary: {e}")
    basic_translator = None

def hash_data(data_str):
    import hashlib
    return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

def get_user_by_token(token):
    if not token: return None
    user_token_hash = hash_data(token)
    return users_collection.find_one({"token_hash": user_token_hash})

def add_to_history(user_id, content_data):
    try:
        encrypted_content = encrypt_user_data(str(user_id), content_data)
        
        history_entry = {
            "content": encrypted_content,
            "created_day": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        users_collection.update_one(
            {"_id": user_id},
            {"$push": {"history": history_entry}}
        )
        return True
    except Exception as e:
        print(f"Error adding to history: {e}")
        return False

def get_user_history(user_id):
    try:
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return []
        
        history = user.get('history', [])
        decrypted_history = []
        
        for entry in history:
            try:
                decrypted_content = decrypt_user_data(str(user_id), entry.get('content', ''))
                decrypted_history.append({
                    "content": decrypted_content,
                    "created_day": entry.get('created_day', '')
                })
            except Exception as e:
                print(f"Error decrypting history entry: {e}")
                continue
        
        return decrypted_history
    except Exception as e:
        print(f"Error getting user history: {e}")
        return []

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
        "note": [],
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

@app.route('/translate_basic', methods=['POST'])
def translate_basic():
    data = request.json
    token = data.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="Invalid or missing token"), 401
    
    text = data.get('text')
    if not text:
        return jsonify(error="Text is required"), 400
    
    if not basic_translator:
        return jsonify(error="Dictionary not available"), 500
    
    try:
        result = basic_translator.translate_text(text)
        
        history_content = {
            "type": "translate_basic",
            "input": text,
            "output": result
        }
        add_to_history(user['_id'], history_content)
        
        return jsonify(translated_data=result), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/translate_advanced', methods=['POST'])
def translate_advanced():
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

        history_content = {
            "type": "translate_advanced",
            "input": text,
            "output": translated_data
        }
        add_to_history(user['_id'], history_content)
        
        return jsonify(translated_data=translated_data), 200
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
        
        history_content = {
            "type": "generate_quiz",
            "difficulty": difficulty,
            "quiz_data": quiz_data
        }
        add_to_history(user['_id'], history_content)
        
        return jsonify(quiz_data), 200
    except json.JSONDecodeError as e:
        app.logger.error(f"JSON Decode Error: {e} - Response text: {cleaned_response}")
        return jsonify(error=f"Failed to parse AI response: {str(e)}"), 500
    except Exception as e:
        app.logger.error(f"Quiz Generation Error: {e}")
        return jsonify(error=f"Failed to generate or parse quiz from AI response: {str(e)}"), 500

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    data = request.json
    token = data.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="Invalid or missing token"), 401
    
    quiz_data = data.get('quiz_data')
    user_answers = data.get('user_answers')
    difficulty = data.get('difficulty', 'A1')
    
    if not quiz_data or not user_answers:
        return jsonify(error="Quiz data and user answers are required"), 400
    
    try:
        evaluation = quiz_manager.evaluate_quiz(quiz_data, user_answers)
        result = quiz_manager.format_quiz_result(difficulty, evaluation)
        
        points_earned = result['score']
        ranking_manager.update_user_points(user['username'], points_earned)
        
        history_content = {
            "type": "submit_quiz",
            "difficulty": difficulty,
            "result": result
        }
        add_to_history(user['_id'], history_content)
        
        return jsonify({
            "result": result,
            "points_earned": points_earned,
            "message": f"Quiz completed! You earned {points_earned} points."
        }), 200
        
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/get_ranking', methods=['GET'])
def get_ranking():
    try:
        top_users = ranking_manager.get_top_users(5)
        stats = ranking_manager.get_ranking_stats()
        
        return jsonify({
            "top_users": top_users,
            "stats": stats
        }), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/view_history', methods=['POST'])
def view_history():
    token = request.json.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404

    try:
        history = get_user_history(user['_id'])
        return jsonify(history=history), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/save_note', methods=['POST'])
def save_note():
    token = request.json.get('token')
    content = request.json.get('content')
    if not content:
        return jsonify(error="Content is required"), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    
    try:
        encrypted_content = encrypt_user_data(str(user['_id']), content)
        
        note_entry = {
            "content": encrypted_content,
            "created_day": datetime.now().strftime("%Y-%m-%d")
        }
        
        users_collection.update_one(
            {"_id": user['_id']},
            {"$push": {"note": note_entry}}
        )
        return jsonify(message="Note saved"), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/view_note', methods=['POST'])
def view_note():
    token = request.json.get('token')
    user = get_user_by_token(token)
    if not user:
        return jsonify(error="User not found"), 404
    
    try:
        notes = user.get('note', [])
        decrypted_notes = []
        
        for note in notes:
            try:
                decrypted_content = decrypt_user_data(str(user['_id']), note.get('content', ''))
                decrypted_notes.append({
                    "content": decrypted_content,
                    "created_day": note.get('created_day', '')
                })
            except Exception as e:
                print(f"Error decrypting note: {e}")
                continue
        
        return jsonify(notes=decrypted_notes), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
