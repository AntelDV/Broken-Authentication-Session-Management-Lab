
# 1. Băm mật khẩu: Gọi hàm md5() từ src/utils/hash_util.py. Không dùng Salt.
# 2. SQL Injection: (Tùy chọn) Có thể code truy vấn DB bằng chuỗi thô (raw string) thay vì ORM.
# 3. User Enumeration: Nếu không thấy username trong DB -> throw exception "Tài khoản không tồn tại".
#    Nếu sai pass -> throw "Sai mật khẩu".
# 4. Session Fixation: Khi login thành công, không tạo session_id mới mà dùng lại session cũ do client gửi lên.
# 5. Rate Limit: Bỏ qua hoàn toàn, cho phép gọi API liên tục.

import uuid
import time
from datetime import datetime, timedelta
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from src.services.base_auth_service import BaseAuthService
from src.repositories.user_repository import UserRepository
from src.repositories.token_repository import TokenRepository
from src.utils.hash_util import hash_md5, verify_md5
from src.security.auth_provider import generate_mfa_secret, get_provisioning_uri, verify_mfa_token
from src.security.jwt_handler import create_access_token, verify_jwt_token

from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest, GoogleSSORequest
from src.schemas.response.auth_response import AuthResponse
from src.models.user import User

class VulnerableAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()
        self.token_repo = TokenRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        user = self.user_repo.get_by_username(db, request.username)
        
        # CWE-203: Trả về lỗi cụ thể giúp hacker dò quét User (Enumeration)
        if not user:
            raise HTTPException(status_code=404, detail="Tài khoản không tồn tại trong hệ thống")
        
        # Giữ lại độ trễ này để tạo ra kẽ hở cho Timing Attack (Kịch bản: User tồn tại thì response chậm hơn)
        time.sleep(0.2)
        
        # CWE-327: Kiểm tra mật khẩu bằng thuật toán yếu MD5
        if not verify_md5(request.password, user.password_hash_vuln):
            # CWE-307: Không khóa tài khoản, cho phép Brute-force vô hạn
            raise HTTPException(status_code=401, detail="Mật khẩu không chính xác")

        if user.is_mfa_enabled:
            temp_token = create_access_token(data={"sub": user.username, "scope": "mfa_pending"})
            return AuthResponse(
                message="Yêu cầu xác thực MFA",
                require_mfa=True, 
                temp_token=temp_token
            )

        access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
        
        # CWE-522: Insufficiently Protected Credentials
        return AuthResponse(
            message="Đăng nhập thành công", 
            session_id=str(uuid.uuid4()), 
            role=user.role.value, 
            access_token=access_token, 
            token_type="bearer"
        )

    def google_sso_login(self, db: Session, request: GoogleSSORequest) -> AuthResponse:
        # CWE-290: Authentication Bypass by Spoofing.
        # Hệ thống tin tưởng hoàn toàn vào trường email do client gửi lên thay vì 
        # giải mã và xác thực chữ ký của google_id_token từ máy chủ Google.
        user = db.query(User).filter(User.email == request.email).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="Email chưa được đăng ký")
        
        if user.is_mfa_enabled:
            temp_token = create_access_token(data={"sub": user.username, "scope": "mfa_pending"})
            return AuthResponse(
                message="Xác thực SSO thành công. Vui lòng nhập OTP để hoàn tất.",
                require_mfa=True, 
                temp_token=temp_token, 
                remember_cookie=None
            )

        # CWE-306: Missing Authentication for Critical Function.
        # Hệ thống bỏ qua hoàn toàn việc kiểm tra trạng thái MFA đối với luồng SSO.
        # Kẻ tấn công có thể giả mạo email để đi thẳng vào hệ thống mà không cần mã OTP.
        access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
        
        return AuthResponse(
            message="Đăng nhập SSO thành công", 
            role=user.role.value,
            access_token=access_token, 
            token_type="bearer"
        )

    def verify_mfa(self, db: Session, request: MFAVerifyRequest) -> dict:
        try:
            payload = verify_jwt_token(request.username) 
            actual_username = payload.get("sub")
        except Exception:
            raise HTTPException(status_code=401, detail="Token không hợp lệ")

        user = self.user_repo.get_by_username(db, actual_username)

        if not user.mfa_secret:
            raise HTTPException(status_code=400, detail="MFA chưa được thiết lập")
            
        if verify_mfa_token(user.mfa_secret, request.otp_token):
            access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
            return {
                "message": "Xác thực MFA thành công", 
                "session_id": str(uuid.uuid4()), 
                "access_token": access_token, 
                "token_type": "bearer", 
                "role": user.role.value
            }
            
        # CWE-307: Improper Restriction of Excessive Authentication Attempts.
        raise HTTPException(status_code=401, detail="Mã OTP không chính xác")

    def setup_mfa(self, db: Session, username: str) -> dict:
        user = self.user_repo.get_by_username(db, username)
        if not user: 
            raise HTTPException(status_code=404, detail="Tài khoản không tồn tại")
            
        if not user.mfa_secret:
            user.mfa_secret = generate_mfa_secret()
            db.commit()
            
        return {
            "message": "Mã thiết lập MFA",
            "secret": user.mfa_secret,
            "qr_uri": get_provisioning_uri(user.username, user.mfa_secret)
        }

    def forgot_password(self, db: Session, request: ForgotPasswordRequest, http_request: Request) -> dict:
        user = db.query(User).filter((User.username == request.username) | (User.email == request.username)).first()
        
        # CWE-203: Báo lỗi thẳng nếu không tìm thấy -> Giúp Hacker biết tài khoản này không tồn tại
        if not user:
            raise HTTPException(status_code=404, detail="Tài khoản không tồn tại")
            
        import random
        import string
        from datetime import datetime, timedelta
        
        # CWE-330: Token khôi phục quá yếu (chỉ 6 số), dễ bị Brute-force
        weak_reset_token = "999" + ''.join(random.choices(string.digits, k=3))
        self.token_repo.create_token(db, user.id, weak_reset_token, datetime.now() + timedelta(minutes=60))
  
        # CWE-644: Host Header Injection (Password Reset Poisoning)
        # Lấy trực tiếp Host từ request gửi lên mà không kiểm duyệt.
        host_header = http_request.headers.get("host", "127.0.0.1:8000") 
        poisoned_link = f"http://{host_header}/reset.html?token={weak_reset_token}"
        
        return {
            "message": "Email khôi phục đã được gửi", 
            "reset_link_demo": poisoned_link
        }

    def reset_password(self, db: Session, request: ResetPasswordRequest) -> dict:
        token_record = self.token_repo.get_token(db, request.token)
        if not token_record:
            raise HTTPException(status_code=400, detail="Token không hợp lệ")
            
        user = db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")
            
        user.password_hash_vuln = hash_md5(request.new_password)
        db.commit()
        
        return {"message": "Mật khẩu đã được cập nhật thành công"}