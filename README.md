# 🛡️ Broken Authentication & Session Management Lab

Dự án này là môi trường thực nghiệm (Lab) được xây dựng bằng Python nhằm minh họa và phân tích các lỗ hổng bảo mật nghiêm trọng liên quan đến Xác thực và Quản lý phiên (OWASP Top 10). 

Dự án được thiết kế theo kiến trúc phân tầng (Layered Architecture) và áp dụng cơ chế "Toggle Mode" cho phép chuyển đổi nhanh giữa phiên bản chứa lỗi (Vulnerable) và phiên bản an toàn (Secure).

## 🎯 Các Lỗ Hổng Minh Họa (Vulnerabilities)
- **CWE-256 / CWE-328:** Lưu trữ mật khẩu dạng Plaintext hoặc MD5 không Salt.
- **CWE-307:** Không giới hạn số lần đăng nhập sai (No Rate Limiting) tạo điều kiện cho Brute-force/Credential Stuffing.
- **CWE-203 / CWE-204:** Thông báo lỗi chi tiết (Verbose Error) dẫn đến User Enumeration.
- **CWE-384 / CWE-613:** Session Fixation và Insufficient Session Expiration.
- **Timing Attack:** Khai thác độ lệch thời gian xử lý hàm băm.

## 🛡️ Cơ Chế Phòng Thủ (Defenses)
- Thuật toán băm an toàn Bcrypt/Argon2id.
- **Rate Limiting** với thuật toán Token Bucket chặn IP.
- Đồng nhất thời gian phản hồi (Fake Delay) và thông báo lỗi chung chung.
- **Hardening Cookie** (HttpOnly, Secure, SameSite) & `session_regenerate_id`.

## 🚀 Hướng Dẫn Cài Đặt
1. Kích hoạt môi trường: `source venv/bin/activate`
2. Cài đặt thư viện: `pip install -r requirements.txt`
3. Chạy server: `uvicorn src.main:app --reload`
