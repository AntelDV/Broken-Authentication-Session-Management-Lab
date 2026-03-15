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

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

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