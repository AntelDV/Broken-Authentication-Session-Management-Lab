# WORKFLOW: Xử lý Request HTTP đầu vào cho Đăng nhập/Đăng ký.
# DATA FLOW: Client -> Controller (nhận LoginRequest) -> Chuyển vào Service tương ứng -> Nhận AuthResponse -> Client.
# CONCEPT: Controller làm nhiệm vụ "điều phối" (Routing).
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest
from src.schemas.response.auth_response import AuthResponse
from src.config.settings import settings
from src.config.database import get_db

from src.services.vulnerable_auth_service import VulnerableAuthService
from src.services.secure_auth_service import SecureAuthService

from pydantic import BaseModel
from src.security.auth_provider import generate_mfa_secret, get_provisioning_uri, verify_mfa_token
from src.models.user import User

import secrets
import hashlib
from datetime import datetime, timedelta
from src.models.password_reset_token import PasswordResetToken
from src.repositories.token_repository import TokenRepository
from src.utils.hash_util import hash_bcrypt, hash_md5


router = APIRouter(prefix="/api/auth", tags=["Authentication"])

token_repo = TokenRepository()

def get_auth_service():
    """
    Gọi Service nào dựa vào file .env.
    """
    if settings.AUTH_MODE == "secure":
        return SecureAuthService()
    return VulnerableAuthService()

@router.post("/login", response_model=AuthResponse)
def login(
    request_data: LoginRequest, 
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    """
    API Đăng nhập 
    """
    return auth_service.login(db, request_data)

class MFAVerifyRequest(BaseModel):
    username: str
    otp_token: str
    
    
# =====================================================================
# API MULTI-FACTOR AUTHENTICATION (MFA)
# =====================================================================

@router.post("/mfa/setup")
def setup_mfa(username: str, db: Session = Depends(get_db)):
    """
    Cấp phát khóa bí mật để người dùng gắn vào Google Authenticator
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    
    # Nếu chưa có secret thì tạo mới và lưu vào DB
    if not user.mfa_secret:
        user.mfa_secret = generate_mfa_secret()
        db.commit()
    
    # Tạo URI để sau này làm mã QR
    qr_uri = get_provisioning_uri(user.username, user.mfa_secret)
    
    return {
        "message": "Vui lòng nhập đoạn mã Secret này vào Google Authenticator hoặc quét mã QR.",
        "secret": user.mfa_secret,
        "qr_uri": qr_uri
    }

@router.post("/mfa/verify")
def verify_mfa(request: MFAVerifyRequest, db: Session = Depends(get_db)):
    """
    Xác thực mã 6 số từ Google Authenticator
    """
    user = db.query(User).filter(User.username == request.username).first()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA chưa được thiết lập cho tài khoản này.")
    
    # Kiểm tra mã OTP
    is_valid = verify_mfa_token(user.mfa_secret, request.otp_token)
    
    if is_valid:
        # Bật cờ đã kích hoạt MFA trong Database
        user.is_mfa_enabled = True
        db.commit()
        return {"message": "✅ Xác thực MFA thành công! Tài khoản của bạn đã được bảo vệ 2 lớp."}
    else:
        raise HTTPException(status_code=401, detail="❌ Mã OTP không chính xác hoặc đã hết hạn.")
    
    
    
class ForgotPasswordRequest(BaseModel):
    username: str
    
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    
    
# =====================================================================
# PASSWORD RESET POISONING
# =====================================================================

@router.post("/password/forgot")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    
    if not user:
        # Không bao giờ báo lỗi "User không tồn tại" ở đây để chống dò quét.
        return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi."}
        
    if settings.AUTH_MODE == "vulnerable":
        # Token quá dễ đoán 
        reset_token = hashlib.md5(user.username.encode()).hexdigest()
        # Token có thời hạn sử dụng lên tới... 10 năm 
        expires = datetime.now() + timedelta(days=3650) 
    else:
        # Sinh chuỗi ngẫu nhiên 32 byte cực mạnh
        reset_token = secrets.token_urlsafe(32)
        # Chỉ sống đúng 15 phút
        expires = datetime.now() + timedelta(minutes=15)
        
    token_repo.create_token(db, user.id, reset_token, expires)
    
    # In ra terminal để test (Giả lập việc gửi email)
    print(f"[EMAIL MOCK] Gửi link khôi phục tới {user.username}: http://127.0.0.1:8000/reset?token={reset_token}")
    
    return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi.", "token_khuyen_mai_de_demo": reset_token}

@router.post("/password/reset")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_record = token_repo.get_token(db, request.token)
    
    if not token_record:
        raise HTTPException(status_code=400, detail="Token không hợp lệ.")
        
    if settings.AUTH_MODE == "secure":
        # kiểm tra tính hợp lệ khắt khe:
        if token_record.is_used:
            raise HTTPException(status_code=400, detail="Token này đã được sử dụng rồi.")
        if datetime.now() > token_record.expires_at:
            raise HTTPException(status_code=400, detail="Token đã hết hạn.")
            
    # Tiến hành đổi mật khẩu
    user = db.query(User).filter(User.id == token_record.user_id).first()
    
    if settings.AUTH_MODE == "vulnerable":
        user.password_hash = hash_md5(request.new_password)
    else:
        user.password_hash = hash_bcrypt(request.new_password)
        
    # Đánh dấu đã sử dụng 
    token_repo.mark_used(db, token_record)
    
    return {"message": "Mật khẩu đã được đặt lại thành công!"}