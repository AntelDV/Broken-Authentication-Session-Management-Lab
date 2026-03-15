#!/bin/bash

echo "🚀 Bắt đầu khởi tạo hệ thống Lab: Broken Authentication & Session Management..."

# 1. Tạo môi trường ảo
echo "📦 Khởi tạo Virtual Environment..."
python3 -m venv venv

# 2. Tạo toàn bộ cấu trúc thư mục
echo "📂 Xây dựng kiến trúc thư mục (Layered Architecture)..."
mkdir -p src/{config,api,services,repositories,models,schemas/{request,response},exceptions,security,middlewares,utils}
mkdir -p scripts

# 3. ROOT FILES (.env, requirements.txt, README.md)
echo "⚙️ Viết các file nền tảng và cấu hình..."

cat << 'EOF' > .env
# Tùy chỉnh môi trường chạy. Chuyển đổi giữa 'vulnerable' và 'secure' để demo.
ENVIRONMENT=development
AUTH_MODE=vulnerable

# Database URL: Khởi đầu với SQLite cho nhẹ, có thể đổi sang MySQL/PostgreSQL sau.
DATABASE_URL=sqlite:///./lab_database.db

# Khóa bí mật ký JWT/Session. Trong thực tế không bao giờ push file này lên Git.
SECRET_KEY=super_secret_key_for_demo_only_12345
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
EOF

cat << 'EOF' > requirements.txt
fastapi
uvicorn
pydantic
pydantic-settings
python-dotenv
passlib[bcrypt]
python-jose[cryptography]
SQLAlchemy
aiohttp
EOF

cat << 'EOF' > README.md
# 🛡️ Broken Authentication & Session Management Lab

Dự án này là môi trường thực nghiệm (Lab) được xây dựng bằng **FastAPI** (Python) nhằm minh họa và phân tích các lỗ hổng bảo mật nghiêm trọng liên quan đến Xác thực và Quản lý phiên (OWASP Top 10). 

Dự án được thiết kế theo kiến trúc phân tầng (Layered Architecture) và áp dụng cơ chế "Toggle Mode" cho phép chuyển đổi mượt mà giữa phiên bản chứa lỗi (Vulnerable) và phiên bản an toàn (Secure).

## 🎯 Các Lỗ Hổng Minh Họa (Vulnerabilities)
- **CWE-256 / CWE-328:** Lưu trữ mật khẩu dạng Plaintext hoặc MD5 không Salt.
- **CWE-307:** Không giới hạn số lần đăng nhập sai (No Rate Limiting) tạo điều kiện cho Brute-force/Credential Stuffing.
- **CWE-203 / CWE-204:** Thông báo lỗi chi tiết (Verbose Error) dẫn đến User Enumeration.
- **CWE-384 / CWE-613:** Session Fixation và Insufficient Session Expiration.
- **Timing Attack:** Khai thác độ lệch thời gian xử lý hàm băm.

## 🛡️ Cơ Chế Phòng Thủ (Defenses)
- Thuật toán băm an toàn **Bcrypt/Argon2id**.
- **Rate Limiting** với thuật toán Token Bucket chặn IP.
- Đồng nhất thời gian phản hồi (Fake Delay) và thông báo lỗi chung chung.
- **Hardening Cookie** (HttpOnly, Secure, SameSite) & `session_regenerate_id`.

## 🚀 Hướng Dẫn Cài Đặt
1. Kích hoạt môi trường: `source venv/bin/activate`
2. Cài đặt thư viện: `pip install -r requirements.txt`
3. Chạy server: `uvicorn src.main:app --reload`
EOF

# 4. CONFIGURATION FILES
cat << 'EOF' > src/config/settings.py
# WORKFLOW: Quản lý toàn bộ cấu hình hệ thống một cách tập trung.
# CONCEPT: Dùng pydantic_settings để tự động map các biến từ file .env vào class Settings.
# ĐIỂM NEO: Biến AUTH_MODE là "công tắc" thần thánh để chúng ta chuyển đổi kịch bản demo.
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "Auth Security Lab"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    AUTH_MODE: str = os.getenv("AUTH_MODE", "vulnerable") 
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./lab_database.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "default_secret")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    class Config:
        env_file = ".env"

settings = Settings()
EOF

cat << 'EOF' > src/config/security_config.py
# WORKFLOW: Nơi thiết lập các config tĩnh về bảo mật.
# ĐIỂM NEO: Nếu mode = 'vulnerable', CORS mở toàn bộ. Ở mode 'secure', sẽ có cấu hình khắt khe hơn.
from fastapi.middleware.cors import CORSMiddleware

def setup_cors(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], 
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

BCRYPT_ROUNDS = 12 # Work Factor chuẩn để chống crack bằng phần cứng.
EOF

cat << 'EOF' > src/main.py
# WORKFLOW: Entry point của ứng dụng.
# 1. Khởi tạo FastAPI app.
# 2. Gắn CORS và các Middleware (như TimingMiddleware, RateLimitMiddleware).
# 3. Include các Router từ thư mục api/.
from fastapi import FastAPI
from src.config.settings import settings
from src.config.security_config import setup_cors

app = FastAPI(title=settings.APP_NAME)
setup_cors(app)

@app.get("/")
def health_check():
    return {"status": "running", "current_mode": settings.AUTH_MODE}
EOF

# 5. API & CONTROLLERS (Tầng giao tiếp)
echo "📝 Viết cấu trúc Controllers và Schemas..."

cat << 'EOF' > src/api/auth_controller.py
# WORKFLOW: Xử lý Request HTTP đầu vào cho Đăng nhập/Đăng ký.
# DATA FLOW: Client -> Controller (nhận LoginRequest) -> Chuyển vào Service tương ứng -> Nhận AuthResponse -> Client.
# CONCEPT: Không bao giờ viết logic truy vấn DB ở đây. Controller chỉ làm nhiệm vụ "điều phối" (Routing).
EOF

cat << 'EOF' > src/api/admin_controller.py
# WORKFLOW: Các API chỉ dành cho Admin. 
# MỤC ĐÍCH: Dùng để test tính năng phân quyền hoặc biểu diễn lỗi cướp phiên (Hijacking) rồi truy cập trái phép.
EOF

cat << 'EOF' > src/schemas/request/login_request.py
# WORKFLOW: Định nghĩa cấu trúc dữ liệu bắt buộc Client phải gửi lên khi Login.
# CONCEPT: Dùng Pydantic để Validate (ví dụ: username không được rỗng, password tối thiểu 6 ký tự).
EOF

cat << 'EOF' > src/schemas/response/auth_response.py
# WORKFLOW: Định nghĩa dữ liệu trả về sau khi Login thành công.
# CONCEPT: Trả về Token hoặc SessionID, tuyệt đối không trả về thông tin nhạy cảm của User.
EOF

# 6. SERVICES (Tầng nghiệp vụ - Linh hồn của hệ thống)
echo "🧠 Viết lõi logic (Vulnerable vs Secure)..."

cat << 'EOF' > src/services/base_auth_service.py
# WORKFLOW: Class Interface (Abstract) định nghĩa các hàm chuẩn (login, register).
# CONCEPT: Ép buộc cả 2 bản Vulnerable và Secure phải code chung một bộ hàm để Controller dễ gọi.
EOF

cat << 'EOF' > src/services/vulnerable_auth_service.py
# ==========================================
# 🚨 VULNERABLE LOGIC (CỐ TÌNH SAI) 🚨
# ==========================================
# LỖI SẼ ĐƯỢC CODE Ở ĐÂY:
# 1. Băm mật khẩu: Gọi hàm md5() từ src/utils/hash_util.py. Không dùng Salt.
# 2. SQL Injection: (Tùy chọn) Có thể code truy vấn DB bằng chuỗi thô (raw string) thay vì ORM.
# 3. User Enumeration: Nếu không thấy username trong DB -> throw exception "Tài khoản không tồn tại".
#    Nếu sai pass -> throw "Sai mật khẩu".
# 4. Session Fixation: Khi login thành công, không tạo session_id mới mà dùng lại session cũ do client gửi lên.
# 5. Rate Limit: Bỏ qua hoàn toàn, cho phép gọi API liên tục.
EOF

cat << 'EOF' > src/services/secure_auth_service.py
# ==========================================
# 🛡️ SECURE LOGIC (BLUE TEAM DEFENSE) 🛡️
# ==========================================
# GIẢI PHÁP ĐƯỢC CODE Ở ĐÂY:
# 1. Băm mật khẩu: Dùng thư viện passlib (Bcrypt) sinh Salt động cho từng user.
# 2. Chống Enumeration: Dù sai user hay sai pass, luông trả về ĐÚNG MỘT câu: "Tài khoản hoặc mật khẩu không chính xác".
# 3. Tái tạo phiên: Khi login thành công, xóa phiên cũ, gen ra một UUID4 mới hoàn toàn.
# 4. Tích hợp với RateLimitMiddleware: Logic này sẽ được bảo vệ bởi bộ lọc chặn IP.
EOF

# 7. REPOSITORIES & MODELS (Tầng dữ liệu)
echo "💾 Viết cấu trúc Database Models..."

cat << 'EOF' > src/models/user.py
# WORKFLOW: Ánh xạ thực thể User thành bảng trong Database (SQLAlchemy).
# CÁC TRƯỜNG DỰ KIẾN: id, username, password_hash, is_active, failed_login_attempts (để hỗ trợ khóa tài khoản).
EOF

cat << 'EOF' > src/repositories/user_repository.py
# WORKFLOW: Chứa các lệnh truy vấn DB thực tế (ví dụ: get_user_by_username).
# CONCEPT: Tách biệt query DB ra khỏi tầng Service để dễ thay đổi Database sau này.
EOF

# 8. MIDDLEWARES & SECURITY (Bảo vệ và can thiệp Request)
echo "🛡️ Thiết lập Middlewares..."

cat << 'EOF' > src/middlewares/rate_limit_middleware.py
# WORKFLOW: MIDDLEWARE CHẶN BRUTE-FORCE.
# HOẠT ĐỘNG:
# 1. Chặn ngay Request trước khi nó kịp chạm tới Controller.
# 2. Trích xuất IP của Client.
# 3. Gọi thuật toán Token Bucket (từ src/security/rate_limit.py) để kiểm tra IP này còn lượt (token) không.
# 4. Nếu hết -> Ném thẳng lỗi HTTP 429 Too Many Requests. Nếu còn -> Trừ 1 token và cho đi tiếp.
EOF

cat << 'EOF' > src/security/rate_limit.py
# WORKFLOW: THUẬT TOÁN TOKEN BUCKET
# CONCEPT: Một biến Dictionary/Redis lưu trữ { "IP_123": { "tokens": 5, "last_refill": timestamp } }
# Hàm check_rate_limit(ip): Tính toán số token hiện tại dựa trên thời gian trôi qua, cập nhật và trả về True/False.
EOF

cat << 'EOF' > src/middlewares/timing_middleware.py
# WORKFLOW: CHỐNG/MÔ PHỎNG TIMING ATTACK.
# CONCEPT:
# Ở mode 'vulnerable': Đo thời gian từ lúc nhận request đến lúc xử lý xong hàm login, in ra log để thấy User tồn tại tốn nhiều ms hơn.
# Ở mode 'secure': Tính toán thời gian xử lý thực, sau đó dùng `time.sleep(độ_trễ_bù_trừ)` để đảm bảo MỌI request đều mất đúng 500ms.
EOF

# 9. SCRIPTS (Red Team / Attacker)
echo "⚔️ Xây dựng vũ khí tấn công..."

cat << 'EOF' > scripts/bruteforce_hydra.sh
#!/bin/bash
# HƯỚNG DẪN TẤN CÔNG BẰNG HYDRA:
# Lệnh tham khảo: hydra -l admin -P wordlist.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Sai mật khẩu" localhost
EOF

cat << 'EOF' > scripts/credential_stuffing.py
# HƯỚNG DẪN CREDENTIAL STUFFING BẰNG AIOHTTP:
# Workflow: Đọc list 10k tài khoản -> asyncio.gather() để bắn 100 request/giây vào endpoint /login.
# Mục đích: Đánh sập Server hoặc thu hoạch các account dùng chung mật khẩu.
EOF

cat << 'EOF' > scripts/timing_attack.py
# HƯỚNG DẪN ĐO ĐỘ LỆCH THỜI GIAN:
# Workflow:
# Vòng lặp 1: Gửi 50 request tới tài khoản 'admin' (Có trong DB) -> Tính Average Time 1.
# Vòng lặp 2: Gửi 50 request tới tài khoản 'no_exist' (Không có trong DB) -> Tính Average Time 2.
# Khẳng định lỗ hổng dựa trên Delta = (Time 1 - Time 2).
EOF

# Chạm để tạo các file rỗng cấu trúc còn lại
touch src/schemas/request/register_request.py
touch src/schemas/response/user_profile_response.py
touch src/exceptions/global_handlers.py
touch src/exceptions/custom_exceptions.py
touch src/security/auth_provider.py
touch src/utils/hash_util.py
touch src/models/password_reset_token.py
touch src/repositories/token_repository.py

chmod +x scripts/bruteforce_hydra.sh

echo "✅ Hệ thống Lab đã được khởi tạo thành công với kiến trúc siêu chi tiết!"

# 10. DOCKER ORCHESTRATION
echo "🐳 Khởi tạo Docker Compose cho môi trường Database..."

cat << 'EOF' > docker-compose.yml
# WORKFLOW: QUẢN LÝ INFRASTRUCTURE NHƯ CODE (IaC)
# 1. Khởi tạo Container MySQL để lưu trữ thông tin người dùng.
# 2. Thiết lập Network để App có thể kết nối với DB qua tên dịch vụ 'db'.
# 3. Sử dụng Volumes để dữ liệu không bị mất khi tắt Container.
# ĐIỂM NEO: Khi chuyển sang dùng MySQL thực tế, hãy cập nhật DATABASE_URL trong .env.
EOF

version: '3.8'

services:
# Tầng Cơ sở dữ liệu (MySQL)
db:
image: mysql:8.0
container_name: auth-lab-db
restart: always
environment:
MYSQL_DATABASE: auth_lab_db
MYSQL_ROOT_PASSWORD: root_password_demo
MYSQL_USER: duong_admin
MYSQL_PASSWORD: secure_password_123
ports:
- "3306:3306"
volumes:
- db_data:/var/lib/mysql

# Tầng Ứng dụng 
app:
build: .
container_name: auth-lab-app
ports:
- "8000:8000"
environment:
- DATABASE_URL=mysql+pymysql://duong_admin:secure_password_123@db:3306/auth_lab_db
- AUTH_MODE=${AUTH_MODE:-vulnerable}
depends_on:
- db

volumes:
db_data:
