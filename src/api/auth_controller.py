# WORKFLOW: Xử lý Request HTTP đầu vào cho Đăng nhập/Đăng ký.
# DATA FLOW: Client -> Controller (nhận LoginRequest) -> Chuyển vào Service tương ứng -> Nhận AuthResponse -> Client.
# CONCEPT: Controller làm nhiệm vụ "điều phối" (Routing).
# WORKFLOW: Xử lý Request HTTP đầu vào cho Đăng nhập/Đăng ký.

from fastapi import APIRouter, Depends, Response, Request
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest
from src.schemas.response.auth_response import AuthResponse
from src.config.settings import settings
from src.config.database import get_db

from src.services.vulnerable_auth_service import VulnerableAuthService
from src.services.secure_auth_service import SecureAuthService
from src.schemas.request.login_request import GoogleSSORequest

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def get_auth_service():
    if settings.AUTH_MODE == "secure":
        return SecureAuthService()
    return VulnerableAuthService()

@router.post("/login", response_model=AuthResponse)
def login(
    request_data: LoginRequest, 
    response: Response, 
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    auth_result = auth_service.login(db, request_data)
    
    is_prod = settings.ENVIRONMENT == "production"

    if settings.AUTH_MODE == "secure":
        # Hardening Cookie & Thiết lập Timeout
        if auth_result.session_id:
            response.set_cookie(
                key="auth_session_id", value=auth_result.session_id,
                httponly=True,       # Chống XSS đọc Cookie
                secure=is_prod,      # Tự động bật cờ Secure (chỉ gửi qua HTTPS)
                samesite="strict",   # Chống CSRF tuyệt đối
                max_age=900          # 15 Phút Timeout tự động đăng xuất nếu không hoạt động
            )
            auth_result.session_id = "[Đã bảo mật trong HttpOnly Cookie]"
            
        if auth_result.remember_cookie:
            response.set_cookie(
                key="remember_me", value=auth_result.remember_cookie,
                httponly=True, secure=is_prod, samesite="strict", max_age=7*24*3600 # Sống 7 ngày
            )
            auth_result.remember_cookie = "[Bảo mật: Chuỗi ngẫu nhiên an toàn]"
    else:
        # Session Persistence 
        if auth_result.session_id:
            response.set_cookie(
                key="auth_session_id", value=auth_result.session_id,
                httponly=False, secure=False, samesite="lax", 
                max_age=34560000    
            )
        if auth_result.remember_cookie:
            response.set_cookie(
                key="remember_me", value=auth_result.remember_cookie,
                httponly=False, secure=False, samesite="lax", max_age=34560000
            )

    return auth_result

@router.post("/mfa/setup")
def setup_mfa(username: str, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.setup_mfa(db, username)

@router.post("/mfa/verify")
def verify_mfa(request: MFAVerifyRequest, response: Response, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    result = auth_service.verify_mfa(db, request)
    
    is_prod = settings.ENVIRONMENT == "production"
    session_id = result.get("session_id")

    if settings.AUTH_MODE == "secure" and session_id:
        response.set_cookie(
            key="auth_session_id", value=session_id,
            httponly=True, secure=is_prod, samesite="strict", max_age=900
        )
        result["session_id"] = "[Đã bảo mật trong HttpOnly Cookie]"
    elif session_id:
        response.set_cookie(
            key="auth_session_id", value=session_id,
            httponly=False, secure=False, samesite="lax", max_age=34560000
        )
        
    return result

@router.post("/password/forgot")
def forgot_password(
    request_data: ForgotPasswordRequest, 
    http_request: Request, # <-- Lấy gói tin HTTP để bóc Header
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    # Truyền thêm http_request xuống Service
    return auth_service.forgot_password(db, request_data, http_request)

@router.post("/password/reset")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.reset_password(db, request)

# SSO
@router.post("/sso/google", response_model=AuthResponse)
def google_sso_login(
    request: GoogleSSORequest, 
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    return auth_service.google_sso_login(db, request)

@router.get("/mock-google-token/{email}")
def get_mock_google_token(email: str):
    """
    giả lập máy chủ Google, 
    trả về 1 ID Token có chữ ký hợp lệ cho email bạn nhập vào.
    """
    from src.security.jwt_handler import create_access_token
    # Nhét email vào Payload và ký
    token = create_access_token(data={"email": email, "iss": "accounts.google.com"})
    return {"google_id_token": token}