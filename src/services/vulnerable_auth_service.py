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

import hashlib
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.services.base_auth_service import BaseAuthService
from src.repositories.user_repository import UserRepository
from src.repositories.token_repository import TokenRepository
from src.utils.hash_util import verify_md5, hash_md5
from src.security.auth_provider import generate_mfa_secret, get_provisioning_uri, verify_mfa_token

from src.security.jwt_handler import create_access_token

from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest, GoogleSSORequest
from src.schemas.response.auth_response import AuthResponse
from src.models.user import User

class VulnerableAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()
        self.token_repo = TokenRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        user = self.user_repo.get_by_username(db, request.username)
        
        if not user:
            raise HTTPException(status_code=404, detail="Tài khoản không tồn tại")
            
        if user.is_locked:
            raise HTTPException(status_code=401, detail="Tài khoản đã bị khóa do nhập sai quá nhiều lần!")

        from src.utils.hash_util import verify_bcrypt, verify_md5
        is_pass_valid = False
        try:
            is_pass_valid = verify_md5(request.password, user.password_hash) or verify_bcrypt(request.password, user.password_hash)
        except:
            is_pass_valid = verify_md5(request.password, user.password_hash)

        if not is_pass_valid:
            attempts = user.failed_login_attempts + 1
            self.user_repo.update_failed_attempts(db, user, attempts, attempts >= 5)
            raise HTTPException(status_code=401, detail="Sai mật khẩu")

        self.user_repo.update_failed_attempts(db, user, 0, False)
        
        fake_vulnerable_session = f"session_of_{user.username}_static"
        
        # Ghép Username và Hash MD5 nhét thẳng vào Cookie
        import base64
        from src.utils.hash_util import hash_md5
        remember_cookie = None
        if request.remember_me:
            # Hacker bắt được cục này sẽ giải mã Base64 và đem MD5 đi crack offline
            raw_cookie = f"{user.username}:{hash_md5(request.password)}"
            remember_cookie = base64.b64encode(raw_cookie.encode()).decode('utf-8')

        fake_vulnerable_session = f"session_of_{user.username}_static"
        
        
        # Sinh JWT Token thực tế chứa thông tin User
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role.value}
        )

        return AuthResponse(
            message="Đăng nhập thành công", 
            session_id=fake_vulnerable_session,
            role=user.role.value,
            remember_cookie=remember_cookie,
            access_token=access_token,   # <-- Cấp JWT
            token_type="bearer"          # <-- OAuth2
        )
        
    def setup_mfa(self, db: Session, username: str) -> dict:
        user = self.user_repo.get_by_username(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User không tồn tại")
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
            
        # Token MD5 dễ đoán và sống 10 năm
        reset_token = hashlib.md5(user.username.encode()).hexdigest()
        self.token_repo.create_token(db, user.id, reset_token, datetime.now() + timedelta(days=3650))
        
        print(f"[EMAIL MOCK] Link khôi phục: http://127.0.0.1:8000/reset?token={reset_token}")
        return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi.", "token_khuyen_mai_de_demo": reset_token}

    def reset_password(self, db: Session, request: ResetPasswordRequest) -> dict:
        token_record = self.token_repo.get_token(db, request.token)
        if not token_record:
            raise HTTPException(status_code=400, detail="Token không hợp lệ.")
            
        # Không kiểm tra hết hạn, không kiểm tra is_used, băm MD5
        user = self.user_repo.get_by_username(db, "admin") # Lấy tạm từ DB
        for u in db.query(user.__class__).all(): # Fix nhanh query
            if u.id == token_record.user_id: user = u
            
        user.password_hash = hash_md5(request.new_password)
        self.token_repo.mark_used(db, token_record)
        return {"message": "Mật khẩu đã được đặt lại thành công!"}
    
    def google_sso_login(self, db: Session, request: GoogleSSORequest) -> AuthResponse:
        user = db.query(User).filter(User.email == request.email).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="Email không tồn tại trong hệ thống")

        from src.security.jwt_handler import create_access_token
        access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
        
        return AuthResponse(
            message="Đăng nhập SSO thành công", 
            role=user.role.value,
            access_token=access_token,
            token_type="bearer"
        )