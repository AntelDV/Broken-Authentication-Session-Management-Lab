# 🛡️ Broken Authentication & Session Management Lab

Môi trường thực nghiệm (Lab) xây dựng bằng **Python (FastAPI)** nhằm minh họa, khai thác và khắc phục các lỗ hổng liên quan đến **Xác thực và Quản lý phiên** (OWASP Top 10 – Identification and Authentication Failures).

Dự án được thiết kế theo **kiến trúc phân tầng** (Controller – Service – Repository) và áp dụng cơ chế **Toggle Mode**, cho phép chuyển nhanh giữa phiên bản chứa lỗi (`vulnerable`) và phiên bản an toàn (`secure`) để so sánh trực tiếp từng kiểu tấn công và cách phòng thủ tương ứng.

## ⚙️ Công Nghệ

- **Backend:** Python, FastAPI, SQLAlchemy
- **Database:** SQLite (chạy local) / MySQL 8.0 (Docker)
- **Bảo mật:** passlib (bcrypt), python-jose (JWT HS256), pyotp (TOTP)
- **Frontend:** HTML/CSS/JavaScript thuần
- **Triển khai:** Docker, Docker Compose

## 🔀 Toggle Mode

- Chế độ mặc định đọc từ biến môi trường `AUTH_MODE` (`vulnerable` hoặc `secure`).
- Có thể đổi chế độ khi đang chạy bằng công tắc trên giao diện hoặc endpoint `POST /api/admin/switch-mode`.
- Mỗi chế độ dùng một service xác thực riêng (`VulnerableAuthService` / `SecureAuthService`), cùng với middleware rate limit, timing và cách cấp phiên tương ứng.

## 🔑 Cơ Chế Xác Thực

Lab sử dụng song song hai cơ chế:

- **Session cookie (stateful):** phiên đăng nhập được lưu và kiểm tra trong database phía server.
- **JWT (HS256):** dùng làm token tạm trong luồng xác thực 2 bước (2FA/TOTP) trước khi cấp phiên chính thức.

## 🎯 Các Lỗ Hổng Minh Họa (`AUTH_MODE=vulnerable`)

### Lưu trữ & xác thực mật khẩu
- **CWE-328 / CWE-916:** Mật khẩu băm bằng **MD5 không Salt**, dễ bị crack bằng rainbow table.
- **CWE-307:** Không giới hạn số lần đăng nhập sai, tạo điều kiện cho Brute-force / Credential Stuffing.
- **CWE-203 / CWE-204:** Thông báo lỗi khác nhau giữa "tài khoản không tồn tại" và "sai mật khẩu" dẫn đến **User Enumeration**.
- **CWE-208:** **Timing Attack**, tài khoản tồn tại phản hồi chậm hơn, cho phép dò tài khoản qua thời gian phản hồi.

### Quản lý phiên
- **CWE-384:** **Session Fixation**, server chấp nhận `session_id` do client cung cấp qua URL hoặc cookie.
- **CWE-613:** **Insufficient Session Expiration**, cookie có thời hạn rất dài, Logout không hủy phiên phía server.
- **CWE-1004 / CWE-614:** Cookie thiếu `HttpOnly`, `Secure`, `SameSite`.

### Xác thực 2 bước (2FA)
- **CWE-347:** JWT tạm của luồng 2FA chấp nhận `alg: none` (không chữ ký), cho phép giả mạo token.
- **CWE-307:** OTP chấp nhận cửa sổ thời gian quá rộng và không giới hạn số lần thử, dẫn đến **Brute-force TOTP**.
- **CWE-304:** **Bypass 2FA**, một số endpoint đăng nhập cấp phiên ngay sau bước mật khẩu mà bỏ qua OTP.

### Khôi phục mật khẩu
- **CWE-640:** **Password Reset Poisoning**, link reset được dựng từ `Host` header do client kiểm soát.
- **CWE-330 / CWE-338:** Token reset dễ đoán (sinh bằng module `random`, không gian giá trị nhỏ), không hết hạn và dùng lại được.

## 🛡️ Cơ Chế Phòng Thủ (`AUTH_MODE=secure`)

- **Bcrypt** (salt động, cost 12) để băm mật khẩu.
- **Account Lockout:** khóa tài khoản sau 5 lần sai mật khẩu/OTP, cập nhật nguyên tử (atomic `UPDATE`) chống race condition.
- **Rate Limiting Token Bucket** theo IP, ghi log tấn công vào bảng `attack_logs`.
- **Chống Enumeration & Timing:** thông báo lỗi chung chung, đệm thời gian phản hồi đăng nhập về cùng một mức.
- **Session Regeneration:** sinh session ID mới sau khi đăng nhập, Logout hủy phiên phía server.
- **Hardening Cookie:** `HttpOnly`, `SameSite=Strict`, thời hạn 15 phút; gắn phiên với IP + User-Agent để phát hiện Session Hijacking.
- **JWT an toàn:** chỉ chấp nhận HS256 có chữ ký hợp lệ; token tạm 2FA bắt buộc `scope=mfa_pending`.
- **Reset Password an toàn:** token sinh bằng `secrets.token_urlsafe(32)`, hạn 15 phút, chỉ dùng một lần, domain cố định.
- **Phân quyền:** API quản trị trả về `403` với tài khoản không phải admin.

## 🚀 Hướng Dẫn Cài Đặt

> ⚠️ **Không chạy `setup_project.sh`**, script này sẽ ghi đè mã nguồn hiện có.

### Cách 1: Chạy local (SQLite)

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Tạo bảng
python -c "from src.config.database import engine; from src.models.user import Base; import src.models.attack_log, src.models.password_reset_token; Base.metadata.create_all(engine)"

# Seed dữ liệu mẫu (5 admin + 1000 user)
python -m src.utils.seed_1k

# Chạy server (chạy ở thư mục gốc repo)
uvicorn src.main:app --reload
```

### Cách 2: Docker Compose (MySQL 8.0)

```bash
AUTH_MODE=vulnerable docker compose up -d --build

# Đợi MySQL khởi động (~20–30 giây), sau đó tạo bảng và seed:
docker compose exec app python -c "from src.config.database import engine; from src.models.user import Base; import src.models.attack_log, src.models.password_reset_token; Base.metadata.create_all(engine)"
docker compose exec app python -m src.utils.seed_1k
```

### Sử dụng

- Giao diện: http://127.0.0.1:8000 · Swagger: http://127.0.0.1:8000/docs
- Tài khoản mẫu: `admin_1` … `admin_5` / `admin123`; `user_1` … `user_1000`. Tất cả đều bật MFA.
- Lấy TOTP secret: `python -m src.get_secret`
- Chuyển chế độ: công tắc trên giao diện, hoặc:

```bash
curl -X POST http://127.0.0.1:8000/api/admin/switch-mode \
  -H "Content-Type: application/json" -d '{"mode":"secure"}'
```

## ⚠️ Cảnh Báo

Dự án chỉ dùng cho mục đích học tập và nghiên cứu.
