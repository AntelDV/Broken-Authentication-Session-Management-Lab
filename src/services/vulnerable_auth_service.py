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

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from src.services.base_auth_service import BaseAuthService
from src.schemas.request.login_request import LoginRequest
from src.schemas.response.auth_response import AuthResponse
from src.repositories.user_repository import UserRepository
from src.utils.hash_util import verify_md5

class VulnerableAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        user = self.user_repo.get_by_username(db, request.username)
        
        # LỖI 1: Trả về lỗi chi tiết "Tài khoản không tồn tại" (Giúp Hacker dò User)
        if not user:
            raise HTTPException(status_code=404, detail="Tài khoản không tồn tại")

        # LỖI 2: Dùng MD5 để kiểm tra mật khẩu (Yếu, dễ crack)
        if not verify_md5(request.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Sai mật khẩu")

        # LỖI 3: Session Fixation (Giả lập việc dùng lại 1 Session ID tĩnh, không an toàn)
        fake_vulnerable_session = f"session_of_{user.username}_static"

        return AuthResponse(
            message="Đăng nhập thành công (Vulnerable Mode)",
            session_id=fake_vulnerable_session,
            role=user.role.value
        )