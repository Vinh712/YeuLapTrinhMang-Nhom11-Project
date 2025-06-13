import threading
import time
from collections import defaultdict
from flask import Flask, request, Response
import requests
import json

# Import shared crypto functions
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

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

# Shared AES encryption key for client-server communication
SHARED_AES_KEY = "SuperFastLTM_2025_SecureKey_32B!"  # 32 bytes key

def create_shared_crypto():
    """
    Tạo AES crypto instance với shared key cho client-server communication
    """
    # Tạo key 32 bytes từ shared secret
    key = hashlib.sha256(SHARED_AES_KEY.encode('utf-8')).digest()
    return AESCrypto(key)

def encrypt_communication_data(data):
    """
    Mã hóa dữ liệu cho communication giữa client và server
    """
    crypto = create_shared_crypto()
    return crypto.encrypt(data)

def decrypt_communication_data(encrypted_data):
    """
    Giải mã dữ liệu từ communication giữa client và server
    """
    crypto = create_shared_crypto()
    return crypto.decrypt(encrypted_data)

class TaskWeightManager:
    """
    Quản lý trọng số công việc cho các server
    """
    
    # Định nghĩa trọng số cho từng loại công việc
    TASK_WEIGHTS = {
        'register': 2,           # Đăng ký user - nhẹ
        'login': 1,              # Đăng nhập - rất nhẹ
        'translate_basic': 3,    # Dịch cơ bản - nhẹ
        'translate_advanced': 8, # Dịch nâng cao (AI) - nặng
        'generate_quiz': 10,     # Tạo quiz (AI) - rất nặng
        'submit_quiz': 4,        # Nộp bài quiz - trung bình
        'view_history': 2,       # Xem lịch sử - nhẹ
        'save_note': 2,          # Lưu ghi chú - nhẹ
        'view_note': 1,          # Xem ghi chú - rất nhẹ
        'get_ranking': 3,        # Lấy ranking - nhẹ
        'default': 5             # Mặc định cho các task khác
    }
    
    def __init__(self):
        self.server_loads = defaultdict(int)  # {server_url: current_load}
        self.lock = threading.Lock()
    
    def get_task_weight(self, endpoint):
        """
        Lấy trọng số của một endpoint
        """
        # Map endpoint to task type
        endpoint_mapping = {
            '/register': 'register',
            '/login': 'login',
            '/translate': 'translate_basic',      # Mặc định là basic
            '/translate_basic': 'translate_basic',
            '/translate_advanced': 'translate_advanced',
            '/generate_quiz': 'generate_quiz',
            '/submit_quiz': 'submit_quiz',
            '/view_history': 'view_history',
            '/save_note': 'save_note',
            '/view_note': 'view_note',
            '/get_ranking': 'get_ranking'
        }
        
        task_type = endpoint_mapping.get(endpoint, 'default')
        return self.TASK_WEIGHTS.get(task_type, self.TASK_WEIGHTS['default'])
    
    def add_task(self, server_url, endpoint):
        """
        Thêm task vào server và tăng load
        """
        weight = self.get_task_weight(endpoint)
        with self.lock:
            self.server_loads[server_url] += weight
        return weight
    
    def complete_task(self, server_url, endpoint):
        """
        Hoàn thành task và giảm load
        """
        weight = self.get_task_weight(endpoint)
        with self.lock:
            self.server_loads[server_url] = max(0, self.server_loads[server_url] - weight)
        return weight
    
    def get_lightest_server(self, servers):
        """
        Lấy server có load nhẹ nhất
        """
        with self.lock:
            # Đảm bảo tất cả servers đều có trong dict
            for server in servers:
                if server not in self.server_loads:
                    self.server_loads[server] = 0
            
            # Tìm server có load thấp nhất
            lightest_server = min(servers, key=lambda s: self.server_loads[s])
            return lightest_server
    
    def get_server_loads(self):
        """
        Lấy thông tin load của tất cả servers
        """
        with self.lock:
            return dict(self.server_loads)

class AdvancedLoadBalancer:
    def __init__(self, servers):
        """
        Khởi tạo load balancer với danh sách servers
        """
        self.servers = servers
        self.task_manager = TaskWeightManager()
        self.app = Flask(__name__)
        self.setup_routes()
    
    def setup_routes(self):
        """
        Thiết lập routes cho load balancer
        """
        @self.app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
        @self.app.route('/<path:path>', methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
        def proxy(path):
            return self.handle_request(path)
        
        @self.app.route('/lb/status', methods=['GET'])
        def status():
            """
            Endpoint để xem trạng thái load balancer
            """
            return {
                'servers': self.servers,
                'server_loads': self.task_manager.get_server_loads(),
                'task_weights': self.task_manager.TASK_WEIGHTS
            }
    
    def handle_request(self, path):
        """
        Xử lý request và chuyển tiếp đến server phù hợp với mã hóa AES đầu cuối
        """
        # Xác định endpoint
        endpoint = f"/{path}" if path else "/"
        
        # Chọn server có load nhẹ nhất
        selected_server = self.task_manager.get_lightest_server(self.servers)
        
        # Thêm task vào server
        task_weight = self.task_manager.add_task(selected_server, endpoint)
        
        try:
            # Tạo URL đầy đủ
            url = f"{selected_server}/{path}"
            
            # Chuẩn bị headers (loại bỏ host header)
            headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
            
            # Xử lý request data với mã hóa AES
            request_data = None
            if request.method in ['POST', 'PUT', 'PATCH']:
                if request.is_json:
                    client_data = request.get_json()
                    
                    # Kiểm tra xem dữ liệu đã được mã hóa chưa
                    if isinstance(client_data, dict) and 'encrypted_data' in client_data:
                        # Giải mã dữ liệu từ client
                        try:
                            decrypted_data = decrypt_communication_data(client_data['encrypted_data'])
                            request_data = decrypted_data
                        except Exception as e:
                            print(f"Decryption error: {e}")
                            return {"error": "Invalid encrypted data"}, 400
                    else:
                        # Dữ liệu chưa mã hóa (backward compatibility)
                        request_data = client_data
                else:
                    request_data = request.get_data()
            
            # Gửi request đến server được chọn
            if request_data is not None:
                if isinstance(request_data, (dict, list)):
                    resp = requests.request(
                        method=request.method,
                        url=url,
                        params=request.args,
                        headers=headers,
                        json=request_data,
                        cookies=request.cookies,
                        allow_redirects=False,
                        timeout=30
                    )
                else:
                    resp = requests.request(
                        method=request.method,
                        url=url,
                        params=request.args,
                        headers=headers,
                        data=request_data,
                        cookies=request.cookies,
                        allow_redirects=False,
                        timeout=30
                    )
            else:
                resp = requests.request(
                    method=request.method,
                    url=url,
                    params=request.args,
                    headers=headers,
                    cookies=request.cookies,
                    allow_redirects=False,
                    timeout=30
                )
            
            # Xử lý response với mã hóa AES
            try:
                response_data = resp.json()
                
                # Mã hóa response trước khi gửi về client
                encrypted_response = encrypt_communication_data(response_data)
                
                return {
                    "encrypted_data": encrypted_response
                }, resp.status_code
                
            except ValueError:
                # Response không phải JSON, trả về như cũ
                excluded_headers = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
                out_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]
                return Response(resp.content, resp.status_code, out_headers)
            
        except requests.exceptions.RequestException as e:
            # Xử lý lỗi kết nối
            print(f"Error connecting to {selected_server}: {e}")
            return {"error": f"Server {selected_server} unavailable"}, 503
            
        finally:
            # Luôn giảm load sau khi hoàn thành (thành công hoặc thất bại)
            self.task_manager.complete_task(selected_server, endpoint)
    
    def run(self, host='0.0.0.0', port=8000, debug=True):
        """
        Chạy load balancer
        """
        print(f"Advanced Load Balancer starting on {host}:{port}")
        print(f"Backend servers: {self.servers}")
        print(f"Task weights: {self.task_manager.TASK_WEIGHTS}")
        self.app.run(host=host, port=port, debug=debug)

# Test và demo
if __name__ == '__main__':
    # Danh sách servers backend
    BACKEND_SERVERS = [
        "http://127.0.0.1:5000",
        "http://127.0.0.1:5001", 
        "http://127.0.0.1:5002",
    ]
    
    # Tạo và chạy load balancer
    load_balancer = AdvancedLoadBalancer(BACKEND_SERVERS)
    
    # Chạy load balancer
    load_balancer.run()

