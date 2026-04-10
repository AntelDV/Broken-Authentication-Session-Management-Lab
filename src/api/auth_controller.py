from fastapi import APIRouter, Depends, HTTPException, Response, Request
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
    request: Request,
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    auth_result = auth_service.login(db, request_data)
    is_prod = settings.ENVIRONMENT == "production"

    if settings.AUTH_MODE == "secure":
        if auth_result.session_id:
            response.set_cookie(
                key="auth_session_id", value=auth_result.session_id,
                httponly=True, secure=is_prod, samesite="strict", max_age=900 
            )
            auth_result.session_id = "[Đã bảo mật trong HttpOnly Cookie]"
            
        if auth_result.remember_cookie:
            response.set_cookie(
                key="remember_me", value=auth_result.remember_cookie,
                httponly=True, secure=is_prod, samesite="strict", max_age=7*24*3600 
            )
            auth_result.remember_cookie = "[Bảo mật: Chuỗi ngẫu nhiên an toàn]"
    else:
        # Ở chế độ cảnh báo: Bắt Session ID từ URL ngay từ bước đăng nhập
        malicious_session_id = request.query_params.get("session_id")
        if malicious_session_id:
            auth_result.session_id = malicious_session_id

        if auth_result.session_id:
            response.set_cookie(
                key="auth_session_id", value=auth_result.session_id,
                httponly=False, secure=False, samesite="lax", max_age=31536000 
            )
        if auth_result.remember_cookie:
            response.set_cookie(
                key="remember_me", value=auth_result.remember_cookie,
                httponly=False, secure=False, samesite="lax", max_age=31536000
            )

    return auth_result

@router.post("/mfa/verify")
def verify_mfa(
    request_data: MFAVerifyRequest, 
    response: Response, 
    request: Request, # Lấy request để bắt param
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    result = auth_service.verify_mfa(db, request_data)
    is_prod = settings.ENVIRONMENT == "production"
    session_id = result.get("session_id")

    if settings.AUTH_MODE == "secure" and session_id:
        response.set_cookie(
            key="auth_session_id", value=session_id,
            httponly=True, secure=is_prod, samesite="strict", max_age=900
        )
        result["session_id"] = "[Đã bảo mật trong HttpOnly Cookie]"
    elif session_id:
        # Ở chế độ cảnh báo: Ưu tiên xài tiếp cái Session ID mà Hacker gắn trên URL
        malicious_session_id = request.query_params.get("session_id")
        final_session_id = malicious_session_id if malicious_session_id else session_id
        
        response.set_cookie(
            key="auth_session_id", value=final_session_id,
            httponly=False, secure=False, samesite="lax", max_age=31536000
        )
        
    return result

@router.post("/mfa/setup")
def setup_mfa(username: str, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.setup_mfa(db, username)

@router.post("/password/forgot")
def forgot_password(
    request_data: ForgotPasswordRequest, 
    http_request: Request,
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    return auth_service.forgot_password(db, request_data, http_request)

@router.post("/password/reset")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db), auth_service = Depends(get_auth_service)):
    return auth_service.reset_password(db, request)

@router.post("/sso/google", response_model=AuthResponse)
def google_sso_login(
    request: GoogleSSORequest, 
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    return auth_service.google_sso_login(db, request)

@router.get("/mock-google-token/{email}")
def get_mock_google_token(email: str):
    from src.security.jwt_handler import create_access_token
    token = create_access_token(data={"email": email, "iss": "accounts.google.com"})
    return {"google_id_token": token}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key="auth_session_id", path="/")
    response.delete_cookie(key="remember_me", path="/")
    return {"message": "Đã đăng xuất an toàn khỏi hệ thống"}