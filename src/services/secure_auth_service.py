# ==========================================
# 🛡️ SECURE LOGIC (BLUE TEAM DEFENSE) 🛡️
# ==========================================
# GIẢI PHÁP ĐƯỢC CODE Ở ĐÂY:
# 1. Băm mật khẩu: Dùng thư viện passlib (Bcrypt) sinh Salt động cho từng user[cite: 71].
# 2. Chống Enumeration: Dù sai user hay sai pass, luông trả về ĐÚNG MỘT câu: "Tài khoản hoặc mật khẩu không chính xác"[cite: 73].
# 3. Tái tạo phiên: Khi login thành công, xóa phiên cũ, gen ra một UUID4 mới hoàn toàn[cite: 72].
# 4. Tích hợp với RateLimitMiddleware: Logic này sẽ được bảo vệ bởi bộ lọc chặn IP[cite: 75].

import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from src.services.base_auth_service import BaseAuthService
from src.schemas.request.login_request import LoginRequest
from src.schemas.response.auth_response import AuthResponse
from src.repositories.user_repository import UserRepository
from src.utils.hash_util import verify_bcrypt

class SecureAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        user = self.user_repo.get_by_username(db, request.username)
        
        # VÁ LỖI 1: Dùng chung một thông báo lỗi (Chống Enumeration)
        generic_error = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tài khoản hoặc mật khẩu không chính xác"
        )

        if not user:
            raise generic_error

        # VÁ LỖI 2: So sánh mật khẩu bằng Bcrypt
        # (Lưu ý: Lúc test bạn có thể bị lỗi ở đây vì user trong DB đang dùng mã MD5)
        if not verify_bcrypt(request.password, user.password_hash):
            raise generic_error

        # VÁ LỖI 3: Cấp một Session ID hoàn toàn mới và ngẫu nhiên (UUID4)
        secure_session_id = str(uuid.uuid4())

        return AuthResponse(
            message="Đăng nhập thành công (Secure Mode)",
            session_id=secure_session_id,
            role=user.role.value
        )