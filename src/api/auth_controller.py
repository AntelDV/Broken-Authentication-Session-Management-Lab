from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest, GoogleSSORequest
from src.schemas.response.auth_response import AuthResponse
from src.config.settings import settings
from src.config.database import get_db
from fastapi import Form
from src.models.user import User, UserSession
import hashlib
import time
import uuid
from src.models.user import User, UserSession
from datetime import datetime, timedelta, timezone

from src.services.vulnerable_auth_service import VulnerableAuthService
from src.services.secure_auth_service import SecureAuthService
from src.security.jwt_handler import verify_jwt_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def get_auth_service():
    if settings.AUTH_MODE == "secure":
        return SecureAuthService()
    return VulnerableAuthService()

def _issue_stateful_session(request: Request, response: Response, db: Session, username: str):
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return
        
        tz_vn = timezone(timedelta(hours=7))
        now_vn = datetime.now(tz_vn).replace(tzinfo=None)
        
        if settings.AUTH_MODE == "secure":
            session_id = str(uuid.uuid4())
            response.set_cookie(key="auth_session_id", value=session_id, httponly=True, max_age=900, samesite="strict", path="/")
            db.query(UserSession).filter(UserSession.user_id == user.id).delete()
            expires_at = datetime.now() + timedelta(minutes=15)
        else:
            url_session = request.query_params.get("session_id")
            cookie_session = request.cookies.get("auth_session_id")
            session_id = url_session or cookie_session or str(uuid.uuid4())
            
            response.set_cookie(key="auth_session_id", value=session_id, httponly=False, max_age=3600*24*365, samesite="lax", path="/")
            expires_at = datetime.now() + timedelta(days=365)
            
        new_session = UserSession(
            session_id=session_id, 
            user_id=user.id,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host,
            expires_at=expires_at
        )
        db.add(new_session)
        db.commit()
    except Exception as e:
        print("Lỗi cấp phát Stateful Session:", e)
        pass


@router.post("/login")
def login(
    request_data: LoginRequest, 
    response: Response, 
    request: Request,
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    auth_result = auth_service.login(db, request_data)
    
    is_mfa_required = False
    if isinstance(auth_result, dict):
        is_mfa_required = auth_result.get("require_mfa", False)
    else:
        is_mfa_required = getattr(auth_result, "require_mfa", False)

    if not is_mfa_required:
        _issue_stateful_session(request, response, db, request_data.username)
        
    return auth_result


@router.post("/mfa/verify")
def verify_mfa(
    request_data: MFAVerifyRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
    auth_service = Depends(get_auth_service)
):
    auth_result = auth_service.verify_mfa(db, request_data)
    from src.security.jwt_handler import verify_jwt_token
    try:
        payload = verify_jwt_token(request_data.username)
        real_username = payload.get("sub")
        
        if real_username:
            _issue_stateful_session(request, response, db, real_username)
    except Exception as e:
        print("Lỗi trích xuất temp_token:", e)
    
    return auth_result

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
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("auth_session_id")
    response.delete_cookie("auth_session_id")
    
    if settings.AUTH_MODE == "secure":
        if session_id:
            db.query(UserSession).filter(UserSession.session_id == session_id).delete()
            db.commit()
        return {"msg": "Đăng xuất an toàn."}
    else:
        return {"msg": "Đăng xuất thành công"}




@router.post("/web-login-vuln")
def login_web_vuln(
    response: Response, 
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...), 
    password: str = Form(...)
):
    vuln_service = VulnerableAuthService()
    login_req = LoginRequest(username=username, password=password)
    
    # Kích hoạt kiểm tra từ Service lỗi. Nếu sai thông tin, 
    # Service tự động văng lỗi 404 hoặc 401 chi tiết ra Client.
    vuln_service.login(db, login_req)
    
    # Nếu vượt qua hàm login phía trên mà không dính Exception -> Đăng nhập đúng
    user = db.query(User).filter(User.username == username).first()
    
    url_session = request.query_params.get("session_id")
    cookie_session = request.cookies.get("auth_session_id")
    session_id = url_session or cookie_session or str(uuid.uuid4())
        
    # Hạn sống 10 năm
    response.set_cookie(
        key="auth_session_id", 
        value=session_id, 
        httponly=False, 
        max_age=3600*24*3650, 
        samesite="lax",
        path="/"
    )
    
    expires_at = datetime.now() + timedelta(days=3650)
    new_session = UserSession(
        session_id=session_id, 
        user_id=user.id,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host,
        expires_at=expires_at
    )
    db.add(new_session)
    db.commit()
    
    return {"msg": "Đăng nhập thành công", "session_id": session_id}


@router.post("/web-login-secure")
def login_web_secure(
    response: Response, 
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...), 
    password: str = Form(...)
):
    secure_service = SecureAuthService()
    login_req = LoginRequest(username=username, password=password)
    
    # Gọi Service an toàn để kiểm tra mật khẩu (Bcrypt) và Rate Limiting.
    secure_service.login(db, login_req)
    
    # Nếu vượt qua dòng trên an toàn -> Xác thực thành công hoàn toàn
    user = db.query(User).filter(User.username == username).first()
    new_session_id = str(uuid.uuid4()) 
    
    # Thiết lập cơ chế Hardening Cookie bảo mật cao
    response.set_cookie(
        key="auth_session_id", 
        value=new_session_id, 
        httponly=True,  
        max_age=900,   # Rút ngắn thời gian sống của Cookie xuống 15 phút
        samesite="strict",
        path="/"
    )
    
    # Giải quyết triệt để tranh chấp luồng dữ liệu (Race Condition) bằng giải pháp cô lập tầng DB
    try:
        db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
        db.commit() 
    except Exception as e:
        db.rollback() 
        print(f"[CẢNH BÁO] Bỏ qua tranh chấp luồng ghi nhận phiên đăng nhập đồng thời: {e}")
    
    # Ép thời gian lưu trữ hết hạn của phiên chuẩn múi giờ Việt Nam (UTC+7)
    tz_vn = timezone(timedelta(hours=7))
    now_vn = datetime.now(tz_vn).replace(tzinfo=None)
    expires_at = now_vn + timedelta(minutes=15) # Đồng bộ thời gian sống 15 phút dưới DB
    
    new_session = UserSession(
        session_id=new_session_id, 
        user_id=user.id,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host,
        expires_at=expires_at
    )
    db.add(new_session)
    db.commit()
    
    return {"msg": "Đăng nhập an toàn thành công", "session_id": new_session_id}