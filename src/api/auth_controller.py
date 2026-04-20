from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest, GoogleSSORequest
from src.schemas.response.auth_response import AuthResponse
from src.config.settings import settings
from src.config.database import get_db


from fastapi import Form
from src.models.user import User, UserSession
from datetime import datetime, timedelta
import hashlib
import time
import uuid
from src.models.user import User, UserSession
from datetime import datetime, timedelta

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
    response: Response, 
    request: Request,
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    auth_result = auth_service.login(db, request_data)
    is_prod = settings.ENVIRONMENT == "production"

    if settings.AUTH_MODE == "secure":
        token_to_cookie = auth_result.temp_token if auth_result.require_mfa else auth_result.access_token
        
        if token_to_cookie:
            response.set_cookie(
                key="session_id", value=token_to_cookie,
                httponly=True, secure=is_prod, samesite="strict", max_age=900
            )
            
            user = db.query(User).filter(User.username == request_data.username).first()
            if user:
                db.query(UserSession).filter(UserSession.session_id == token_to_cookie).delete() 
                new_session = UserSession(
                    session_id=token_to_cookie,
                    user_id=user.id,
                    user_agent=request.headers.get("user-agent", "Unknown"),
                    ip_address=request.client.host,
                    expires_at=datetime.now() + timedelta(minutes=15) 
                )
                db.add(new_session)
                db.commit()

            if auth_result.access_token: auth_result.access_token = "[Đã bảo mật trong HttpOnly Cookie]"
            if auth_result.temp_token: auth_result.temp_token = "[Đã bảo mật trong HttpOnly Cookie]"
            if auth_result.session_id: auth_result.session_id = "[Đã bảo mật trong HttpOnly Cookie]"
            
    else:
        malicious_id_url = request.query_params.get("session_id")
        malicious_id_cookie = request.cookies.get("session_id")
        
        final_hacker_id = malicious_id_url if malicious_id_url else malicious_id_cookie
        
        if final_hacker_id:
            auth_result.session_id = final_hacker_id

        if auth_result.session_id:
            response.set_cookie(
                key="session_id", value=auth_result.session_id,
                httponly=False, secure=False, samesite="lax", max_age=31536000
            )

            user = db.query(User).filter(User.username == request_data.username).first()
            if user:
                db.query(UserSession).filter(UserSession.session_id == auth_result.session_id).delete()
                new_session = UserSession(
                    session_id=auth_result.session_id,
                    user_id=user.id,
                    user_agent=request.headers.get("user-agent", "Unknown"),
                    ip_address=request.client.host,
                    expires_at=datetime.now() + timedelta(days=3650)
                )
                db.add(new_session)
                db.commit()
            

    return auth_result

@router.post("/mfa/verify")
def verify_mfa(
    request_data: MFAVerifyRequest, 
    response: Response, 
    request: Request,
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    is_prod = settings.ENVIRONMENT == "production"

    if settings.AUTH_MODE == "secure":
        secure_temp_token = request.cookies.get("auth_session_id")
        if secure_temp_token:
            request_data.username = secure_temp_token 
        elif "[Đã bảo mật" in request_data.username:
            raise HTTPException(status_code=401, detail="Trình duyệt chặn Cookie. Vui lòng thử lại!")
            
    result = auth_service.verify_mfa(db, request_data)

    if settings.AUTH_MODE == "secure":
        real_access_token = result.get("access_token")
        if real_access_token:
            response.set_cookie(
                key="auth_session_id", value=real_access_token,
                httponly=True, secure=is_prod, samesite="strict", max_age=900
            )
            result["access_token"] = "[Đã bảo mật trong HttpOnly Cookie]"
            result["session_id"] = "[Đã bảo mật trong HttpOnly Cookie]"
    else:
        malicious_id_url = request.query_params.get("session_id")
        malicious_id_cookie = request.cookies.get("auth_session_id")
        
        final_hacker_id = malicious_id_url if malicious_id_url else malicious_id_cookie
        if not final_hacker_id:
            final_hacker_id = result.get("session_id")
            
        result["session_id"] = final_hacker_id
        response.set_cookie(
            key="auth_session_id", value=final_hacker_id,
            httponly=False, secure=False, samesite="lax", max_age=31536000
        )
        
    return result

@router.post("/sso/google", response_model=AuthResponse)
def google_sso_login(
    request_data: GoogleSSORequest, 
    response: Response,
    request: Request,
    db: Session = Depends(get_db), 
    auth_service = Depends(get_auth_service)
):
    auth_result = auth_service.google_sso_login(db, request_data)
    is_prod = settings.ENVIRONMENT == "production"

    if settings.AUTH_MODE == "secure":
        token_to_cookie = auth_result.temp_token if auth_result.require_mfa else auth_result.access_token
        
        if token_to_cookie:
            response.set_cookie(
                key="auth_session_id", value=token_to_cookie,
                httponly=True, secure=is_prod, samesite="strict", max_age=900
            )
            if auth_result.access_token: auth_result.access_token = "[Đã bảo mật trong HttpOnly Cookie]"
            if auth_result.temp_token: auth_result.temp_token = "[Đã bảo mật trong HttpOnly Cookie]"
            if auth_result.session_id: auth_result.session_id = "[Đã bảo mật trong HttpOnly Cookie]"
    else:
        malicious_id_url = request.query_params.get("session_id")
        malicious_id_cookie = request.cookies.get("auth_session_id")
        final_hacker_id = malicious_id_url if malicious_id_url else malicious_id_cookie
        
        if final_hacker_id:
            auth_result.session_id = final_hacker_id

        if auth_result.session_id:
            response.set_cookie(
                key="auth_session_id", value=auth_result.session_id,
                httponly=False, secure=False, samesite="lax", max_age=31536000
            )

    return auth_result

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



@router.post("/web-login-vuln")
def login_web_vulnerable(
    response: Response, 
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...), 
    password: str = Form(...)
):
    user = db.query(User).filter(User.username == username).first()
    if user: 
        malicious_id = request.query_params.get("session_id")
        
        if malicious_id:
            session_id = malicious_id
        else:
            session_id = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
            
        response.set_cookie(key="session_id", value=session_id)
        
        expires_at = datetime.now() + timedelta(days=3650)
        
        new_session = UserSession(
            session_id=session_id, 
            user_id=user.id,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host,
            expires_at=expires_at
        )
        db.query(UserSession).filter(UserSession.session_id == session_id).delete()
        
        db.add(new_session)
        db.commit()
        
        return {"msg": "Đăng nhập Web thành công", "session_id": session_id}
    return {"error": "Sai tài khoản"}


@router.post("/web-login-secure")
def login_web_secure(
    response: Response, 
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...), 
    password: str = Form(...)
):
    user = db.query(User).filter(User.username == username).first()
    if user:
        new_session_id = str(uuid.uuid4()) 
        
        response.set_cookie(key="session_id", value=new_session_id, httponly=True, max_age=3600, samesite="lax")
        
        expires_at = datetime.now() + timedelta(hours=1)
        
        new_session = UserSession(
            session_id=new_session_id, 
            user_id=user.id,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host,
            expires_at=expires_at
        )
        db.add(new_session)
        db.commit()
        
        return {"msg": "Đăng nhập an toàn. Đã tái tạo phiên."}
    return {"error": "Sai tài khoản"}