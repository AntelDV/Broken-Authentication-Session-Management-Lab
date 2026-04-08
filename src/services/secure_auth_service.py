
import uuid
import secrets
import time
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from fastapi import Request
from sqlalchemy.orm import Session
from passlib.exc import UnknownHashError

from src.services.base_auth_service import BaseAuthService
from src.repositories.user_repository import UserRepository
from src.repositories.token_repository import TokenRepository
from src.utils.hash_util import verify_bcrypt, hash_bcrypt, hash_md5, verify_md5
from src.security.auth_provider import generate_mfa_secret, get_provisioning_uri, verify_mfa_token

from src.security.jwt_handler import create_access_token
from src.security.jwt_handler import verify_jwt_token

from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest, GoogleSSORequest
from src.schemas.response.auth_response import AuthResponse
from src.models.user import User
from src.utils.hash_util import verify_bcrypt

             
class SecureAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()
        self.token_repo = TokenRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        # Bắt đầu bấm giờ để tính toán độ trễ
        start_time = time.time() 
        
        user = self.user_repo.get_by_username(db, request.username)
        
        # Dùng chung một thông báo lỗi để che giấu thông tin chống Enumeration
        generic_error = HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác")

        try:
            # Kiểm tra tài khoản tồn tại hoặc bị khóa
            if not user or user.is_locked: 
                raise generic_error
                
            # Kiểm tra mật khẩu Bcrypt
            is_pass_valid = False
            try:
                is_pass_valid = verify_bcrypt(request.password, user.password_hash)
            except UnknownHashError:
                # Nếu User này được tạo từ thời hệ thống còn yếu kém (dùng MD5)
                is_pass_valid = verify_md5(request.password, user.password_hash)

            if not is_pass_valid:
                attempts = user.failed_login_attempts + 1
                self.user_repo.update_failed_attempts(db, user, attempts, attempts >= 5)
                raise generic_error
            # ----------------------------------------------
                
            # Reset số lần sai nếu đăng nhập đúng
            self.user_repo.update_failed_attempts(db, user, 0, False)

            # Tạo cookie ghi nhớ an toàn
            remember_cookie = secrets.token_urlsafe(64) if request.remember_me else None

            # Chặn lại đòi mã OTP nếu tài khoản có bật MFA
            if user.is_mfa_enabled:
                mfa_temp_token = create_access_token(data={"sub": user.username, "scope": "mfa_pending"})
                return AuthResponse(
                    message="Vui lòng nhập mã bảo mật để hoàn tất",
                    require_mfa=True, 
                    temp_token=mfa_temp_token, 
                    remember_cookie=remember_cookie
                )

            # Cấp quyền truy cập nếu vượt qua mọi rào cản
            access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
            return AuthResponse(
                message="Đăng nhập thành công", 
                session_id=str(uuid.uuid4()), 
                role=user.role.value, 
                remember_cookie=remember_cookie, 
                access_token=access_token, 
                token_type="bearer"
            )
            
        finally:
            # Luôn bắt máy chủ đợi đủ 0.5 giây trước khi trả kết quả
            elapsed = time.time() - start_time
            if elapsed < 0.5:
                time.sleep(0.5 - elapsed)
    
    
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
        try:
            payload = verify_jwt_token(request.username) 
            if payload.get("scope") != "mfa_pending": raise Exception()
            actual_username = payload.get("sub")
        except Exception:
            raise HTTPException(status_code=401, detail="Phiên xác thực OTP đã hết hạn hoặc không hợp lệ!")

        user = self.user_repo.get_by_username(db, actual_username)
        
        if not user or user.is_locked:
            raise HTTPException(status_code=401, detail="Tài khoản đã bị khóa do nhập sai OTP quá nhiều lần.")

        if not user.mfa_secret:
            raise HTTPException(status_code=400, detail="MFA chưa được thiết lập.")
            
        if verify_mfa_token(user.mfa_secret, request.otp_token):
            self.user_repo.update_failed_attempts(db, user, 0, False)
            user.is_mfa_enabled = True
            db.commit()
            from src.security.jwt_handler import create_access_token
            access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
            return {
                "message": "Xác thực MFA thành công!", "session_id": str(uuid.uuid4()), 
                "access_token": access_token, "token_type": "bearer", "role": user.role.value
            }
            
        attempts = user.failed_login_attempts + 1
        self.user_repo.update_failed_attempts(db, user, attempts, attempts >= 5)
        
        if attempts >= 5:
            raise HTTPException(status_code=401, detail="Tài khoản đã bị khóa bảo vệ do nhập sai OTP 5 lần!")
        else:
            raise HTTPException(status_code=401, detail=f"Mã OTP không chính xác. Bạn còn {5 - attempts} lần thử.")

    def forgot_password(self, db: Session, request: ForgotPasswordRequest, http_request: Request) -> dict:
        user = self.user_repo.get_by_username(db, request.username)
        if not user:
            return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi."}
            
        reset_token = secrets.token_urlsafe(32)
        self.token_repo.create_token(db, user.id, reset_token, datetime.now() + timedelta(minutes=15))
  
        SAFE_DOMAIN = "127.0.0.1:8000" 
        secure_link = f"http://{SAFE_DOMAIN}/reset?token={reset_token}"
        
        print(f"[EMAIL] Link khôi phục an toàn: {secure_link}")
        return {
            "message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi.", 
            "reset_link_demo": secure_link
        }

    def reset_password(self, db: Session, request: ResetPasswordRequest) -> dict:
        token_record = self.token_repo.get_token(db, request.token)
        if not token_record:
            raise HTTPException(status_code=400, detail="Token không hợp lệ.")
            
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
    

    def google_sso_login(self, db: Session, request: GoogleSSORequest) -> AuthResponse:
        try:
            from src.security.jwt_handler import verify_jwt_token
            payload = verify_jwt_token(request.google_id_token)
            verified_email = payload.get("email") 
        except Exception:
            raise HTTPException(status_code=401, detail="Google Token không hợp lệ hoặc bị giả mạo!")

        user = db.query(User).filter(User.email == verified_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Email không tồn tại trong hệ thống")

        if user.is_mfa_enabled:
            from src.security.jwt_handler import create_access_token
            mfa_temp_token = create_access_token(data={"sub": user.username, "scope": "mfa_pending"})
            return AuthResponse(
                message="Xác thực SSO thành công. Vui lòng nhập OTP để hoàn tất.",
                require_mfa=True, 
                temp_token=mfa_temp_token, 
                remember_cookie=None
            )

        from src.security.jwt_handler import create_access_token
        access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
        
        return AuthResponse(
            message="Đăng nhập SSO thành công", 
            role=user.role.value,
            access_token=access_token, 
            token_type="bearer"
        )