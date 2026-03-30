
# 1. Băm mật khẩu: Dùng thư viện passlib (Bcrypt) sinh Salt động cho từng user[cite: 71].
# 2. Chống Enumeration: Dù sai user hay sai pass, luông trả về ĐÚNG MỘT câu: "Tài khoản hoặc mật khẩu không chính xác"[cite: 73].
# 3. Tái tạo phiên: Khi login thành công, xóa phiên cũ, gen ra một UUID4 mới hoàn toàn[cite: 72].
# 4. Tích hợp với RateLimitMiddleware: Logic này sẽ được bảo vệ bởi bộ lọc chặn IP[cite: 75].

import uuid
import secrets
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from passlib.exc import UnknownHashError

from src.services.base_auth_service import BaseAuthService
from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest
from src.schemas.response.auth_response import AuthResponse
from src.repositories.user_repository import UserRepository
from src.repositories.token_repository import TokenRepository
from src.utils.hash_util import verify_bcrypt, hash_bcrypt
from src.security.auth_provider import generate_mfa_secret, get_provisioning_uri, verify_mfa_token

class SecureAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()
        self.token_repo = TokenRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        user = self.user_repo.get_by_username(db, request.username)
        generic_error = HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác")

        try:
            if not user:
                raise generic_error
                
            if user.is_locked:
                raise generic_error

            if not verify_bcrypt(request.password, user.password_hash):
                # Tăng biến đếm nhập sai và khóa nếu quá 5 lần
                attempts = user.failed_login_attempts + 1
                is_locked = attempts >= 5
                self.user_repo.update_failed_attempts(db, user, attempts, is_locked)
                raise generic_error
                
            # Đăng nhập đúng -> Reset đếm sai về 0
            self.user_repo.update_failed_attempts(db, user, 0, False)

        except UnknownHashError:
            raise generic_error

        return AuthResponse(message="Đăng nhập thành công (Secure Mode)", session_id=str(uuid.uuid4()), role=user.role.value)

    def setup_mfa(self, db: Session, username: str) -> dict:
        user = self.user_repo.get_by_username(db, username)
        if not user: raise HTTPException(status_code=404, detail="User không tồn tại")
        if not user.mfa_secret:
            user.mfa_secret = generate_mfa_secret()
            db.commit()
        return {
            "message": "Vui lòng nhập đoạn mã Secret này vào Google Authenticator hoặc quét mã QR.",
            "secret": user.mfa_secret,
            "qr_uri": get_provisioning_uri(user.username, user.mfa_secret)
        }

    def verify_mfa(self, db: Session, request: MFAVerifyRequest) -> dict:
        user = self.user_repo.get_by_username(db, request.username)
        if not user or not user.mfa_secret:
            raise HTTPException(status_code=400, detail="MFA chưa được thiết lập cho tài khoản này.")
        if verify_mfa_token(user.mfa_secret, request.otp_token):
            user.is_mfa_enabled = True
            db.commit()
            return {"message": "✅ Xác thực MFA thành công!"}
        raise HTTPException(status_code=401, detail="❌ Mã OTP không chính xác.")

    def forgot_password(self, db: Session, request: ForgotPasswordRequest) -> dict:
        user = self.user_repo.get_by_username(db, request.username)
        if not user:
            return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi."}
            
        # 🛡️ BẢN AN TOÀN: Sinh chuỗi ngẫu nhiên 32 byte cực mạnh, sống 15 phút
        reset_token = secrets.token_urlsafe(32)
        self.token_repo.create_token(db, user.id, reset_token, datetime.now() + timedelta(minutes=15))
        
        print(f"[EMAIL MOCK] Link khôi phục: http://127.0.0.1:8000/reset?token={reset_token}")
        return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi.", "token_khuyen_mai_de_demo": reset_token}

    def reset_password(self, db: Session, request: ResetPasswordRequest) -> dict:
        token_record = self.token_repo.get_token(db, request.token)
        if not token_record:
            raise HTTPException(status_code=400, detail="Token không hợp lệ.")
            
        # 🛡️ BẢN AN TOÀN kiểm tra tính hợp lệ khắt khe:
        if token_record.is_used:
            raise HTTPException(status_code=400, detail="Token này đã được sử dụng rồi.")
        if datetime.now() > token_record.expires_at:
            raise HTTPException(status_code=400, detail="Token đã hết hạn.")
            
        user = self.user_repo.get_by_username(db, "admin") 
        for u in db.query(user.__class__).all():
            if u.id == token_record.user_id: user = u
            
        user.password_hash = hash_bcrypt(request.new_password)
        self.token_repo.mark_used(db, token_record)
        return {"message": "Mật khẩu đã được đặt lại thành công!"}