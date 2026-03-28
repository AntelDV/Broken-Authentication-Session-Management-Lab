# WORKFLOW: Xử lý Request HTTP đầu vào cho Đăng nhập/Đăng ký.
# DATA FLOW: Client -> Controller (nhận LoginRequest) -> Chuyển vào Service tương ứng -> Nhận AuthResponse -> Client.
# CONCEPT: Controller làm nhiệm vụ "điều phối" (Routing).
# WORKFLOW: Xử lý Request HTTP đầu vào cho Đăng nhập/Đăng ký.

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest
from src.schemas.response.auth_response import AuthResponse
from src.config.settings import settings
from src.config.database import get_db

from src.services.vulnerable_auth_service import VulnerableAuthService
from src.services.secure_auth_service import SecureAuthService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def get_auth_service():
    if settings.AUTH_MODE == "secure":
        return SecureAuthService()
    return VulnerableAuthService()

@router.post("/login", response_model=AuthResponse)
def login(
    request_data: LoginRequest, 
    response: Response, # Thêm tham số này để can thiệp Cookie
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    """
    API Đăng nhập (Có hỗ trợ HttpOnly Cookie)
    """
    auth_result = auth_service.login(db, request_data)
    
    if settings.AUTH_MODE == "secure":
        # Nhét Session ID vào HttpOnly Cookie
        response.set_cookie(
            key="auth_session_id",
            value=auth_result.session_id,
            httponly=True,  
            secure=False,   
            samesite="lax", 
            max_age=3600    
        )
        # Giấu Session ID khỏi Body JSON 
        auth_result.session_id = "[Đã được bảo mật trong HttpOnly Cookie]"
        
    return auth_result

@router.post("/mfa/setup")
def setup_mfa(username: str, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.setup_mfa(db, username)

@router.post("/mfa/verify")
def verify_mfa(request: MFAVerifyRequest, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.verify_mfa(db, request)

@router.post("/password/forgot")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.forgot_password(db, request)

@router.post("/password/reset")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.reset_password(db, request)