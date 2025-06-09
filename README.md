# SuperFastLTM Client-Server Application

## Giới thiệu
`SuperFastLTM` là một hệ thống client-server hỗ trợ tra từ, dịch văn bản và tạo quiz tiếng Anh, bao gồm:

- **Backend (Flask)**: Xử lý đăng ký, đăng nhập, dịch văn bản, tạo quiz, quản lý lịch sử và ghi chú người dùng.
- **Load Balancer**: Phân phối yêu cầu HTTP qua ba instance server theo thuật toán Round Robin.
- **Client (PyQt5)**: Giao diện desktop cho phép:
  - Nhập/văn bản cần dịch và tự động dịch qua phím tắt
  - Tạo quiz theo cấp độ ngôn ngữ
  - Xem lịch sử thao tác
  - Ghi chú cá nhân

## Công nghệ sử dụng
- **Ngôn ngữ**: Python 3.10+
- **Framework backend**: Flask
- **Cơ sở dữ liệu**: MongoDB Atlas (PyMongo)
- **API tạo nội dung**: Google Generative AI (Gemini)
- **Load Balancer**: Flask + `requests`
- **Client UI**: PyQt5 + QThread + `keyboard` + `pyperclip`

## Cấu trúc thư mục
```
/project-root
├── server.py           # Backend chính (Flask)
├── load_balencer.py    # Reverse proxy Round Robin
├── client.py           # Ứng dụng desktop (PyQt5)
├── requirements.txt    # Danh sách phụ thuộc
└── README.md           # Tài liệu này
```

## Chi tiết chức năng và luồng xử lý

### 1. App Logic (Luồng nghiệp vụ)

#### 1.1 Đăng ký (Register)
- **Endpoint**: `POST /register`
- **Input**: JSON `{ "username": <string>, "password": <string> }`
- **Xử lý**:
  1. Kiểm tra `username` và `password` không rỗng.
  2. Kiểm tra xem `username` đã tồn tại trong MongoDB.
  3. Hash `password` bằng SHA‑256.
  4. Tạo bản ghi người dùng mới với các trường: `username`, `password`(hash), `point`, `history`, `note`, `role`.
  5. Trả về HTTP 201 với thông điệp thành công.

#### 1.2 Đăng nhập (Login)
- **Endpoint**: `POST /login`
- **Input**: JSON `{ "username": <string>, "password": <string> }`
- **Xử lý**:
  1. Xác thực `username` và `password` (so sánh hash).
  2. Tạo `token` (SHA‑256 của user ID).
  3. Trả về HTTP 200 với `token`.

#### 1.3 Dịch văn bản (Translate)
- **Endpoint**: `POST /translate`
- **Input**: JSON `{ "text": <string>, "from_lang": <string>, "to_lang": <string> }`
- **Xử lý**:
  1. Xây prompt dịch phù hợp (từ/câu, IPA, đa lựa chọn).
  2. Gọi Gemini API để sinh kết quả.
  3. Trả về bản dịch.

#### 1.4 Tạo Quiz (Generate Quiz)
- **Endpoint**: `POST /generate_quiz`
- **Input**: JSON `{ "difficulty": "A1"|...|"C2" }`
- **Xử lý**: Gọi Gemini API để tạo 4 câu hỏi trắc nghiệm, trả về dạng text.

#### 1.5 Lịch sử & Ghi chú
- **Add/View History**: `POST /add_history` và `POST /view_history`
- **Add/View Note**: `POST /add_note` và `POST /view_note`
- Push và pull dữ liệu từ các mảng `history` và `note` trong MongoDB.

### 2. Socket & Network Logic

#### 2.1 Client-side (PyQt5 + QThread)
- **HotkeyListener** (QThread) lắng nghe `Ctrl+B`, copy vùng chọn, emit signal.
- **UI**: Khi nhận signal, bật tab Translate, đẩy text và gọi API.

#### 2.2 HTTP Communication (`requests`)
- Client thực hiện các `POST` tới server cho tất cả các chức năng: register, login, translate, quiz, history, note.

#### 2.3 Load Balancer (Round Robin)
- Proxy đọc danh sách 3 backend (`5000`, `5001`, `5002`), lặp vòng tròn.
- Forward request giữ nguyên method, headers, body.
- Loại bỏ hop-by-hop headers trước khi trả về client.

## Tiêu chí chất lượng
Bảng dưới đây tóm tắt các tiêu chí đánh giá chính của hệ thống:

| Tiêu chí                   | Mô tả ngắn gọn                                   |
|----------------------------|--------------------------------------------------|
| App Logic + Socket Logic   | Nghiệp vụ chính và xử lý phím tắt, I/O mạng      |
| I/O (File, Network)        | HTTP requests/responses, clipboard capture        |
| Database                   | Lưu trữ và truy xuất MongoDB                      |
| Thread                     | Hotkey listener không chặn UI                    |
| Sign up/Sign in            | Đăng ký, đăng nhập, token-based auth             |
| Multi Client               | Hỗ trợ nhiều client, phân biệt bằng token         |
| Multi Server               | Ba instance backend chạy song song               |
| Cryptography               | Hash SHA‑256 cho mật khẩu và token                |
| Demo via LAN/Internet      | Chạy trên LAN và gọi API Internet                 |
| Load Balancing             | Round Robin phân phối request                    |
