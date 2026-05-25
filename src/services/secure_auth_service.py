import uuid
import secrets
import time
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from fastapi import Request
from sqlalchemy.orm import Session
from sqlalchemy import update
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

             
class SecureAuthService(BaseAuthService):
    def __init__(self):
        self.user_repo = UserRepository()
        self.token_repo = TokenRepository()

    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        user = self.user_repo.get_by_username(db, request.username)
        
        # Dùng chung 1 thông báo để hacker không biết là sai User hay sai Pass
        generic_error = HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác")

        # Chặn ngay nếu tài khoản không tồn tại hoặc đã bị khóa 
        if not user or user.is_locked: 
            raise generic_error
            
        # Trỏ đúng vào cột Bcrypt (Bỏ cơ chế fallback MD5 cũ gây lỗi)
        is_pass_valid = verify_bcrypt(request.password, user.password_hash_secure)

        # Nếu nhập sai Pass
        if not is_pass_valid:
            db.execute(
                update(User).where(User.id == user.id).values(
                    failed_login_attempts=User.failed_login_attempts + 1,
                    is_locked=(User.failed_login_attempts + 1 >= 5)
                )
            )
            db.commit()
            raise generic_error
            
        # Đăng nhập đúng thì reset số lần sai về 0
        if user.failed_login_attempts > 0:
            self.user_repo.update_failed_attempts(db, user, 0, False)

        remember_cookie = secrets.token_urlsafe(64) if request.remember_me else None

        # Yêu cầu xác thực điện thoại (2FA)
        if user.is_mfa_enabled:
            mfa_temp_token = create_access_token(data={"sub": user.username, "scope": "mfa_pending"})
            return AuthResponse(
                message="Vui lòng nhập mã bảo mật để hoàn tất",
                require_mfa=True, 
                temp_token=mfa_temp_token, 
                remember_cookie=remember_cookie
            )

        access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
        return AuthResponse(
            message="Đăng nhập thành công", 
            session_id=str(uuid.uuid4()), 
            role=user.role.value, 
            remember_cookie=remember_cookie, 
            access_token=access_token, 
            token_type="bearer"
        )
        
        # Sinh một UUID ngắn gọn làm Session ID thực sự lưu dưới DB
        new_session_id = str(uuid.uuid4())
        
        # Nhét cái Session ID đó vào trong bụng của JWT
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role.value, "session_id": new_session_id}
        )
        
        return AuthResponse(
            message="Đăng nhập thành công", 
            session_id=new_session_id, # Trả về UUID, không phải JWT khổng lồ
            role=user.role.value, 
            remember_cookie=remember_cookie, 
            access_token=access_token, 
            token_type="bearer"
        )
    

    def google_sso_login(self, db: Session, request: GoogleSSORequest) -> AuthResponse:
        try:
            # Không tin cái email mà Frontend gửi lên. 
            # Bắt buộc tháo tung cái Token của Google ra để lấy email thật sự bên trong.
            payload = verify_jwt_token(request.google_id_token)
            verified_email = payload.get("email") 
        except Exception:
            raise HTTPException(status_code=401, detail="Google Token không hợp lệ hoặc bị giả mạo!")

        user = db.query(User).filter(User.email == verified_email).first()
        
        # Chặn ngay nếu email Google đó chưa được đăng ký trong hệ thống hoặc bị khóa
        if not user or user.is_locked:
            raise HTTPException(status_code=401, detail="Tài khoản không hợp lệ hoặc đã bị khóa")

        # Đăng nhập SSO thành công cũng xóa cờ nhập sai cho DB sạch sẽ
        if user.failed_login_attempts > 0:
            self.user_repo.update_failed_attempts(db, user, 0, False)

        # SSO xong vẫn phải hỏi OTP nếu tài khoản có bật bảo mật 2 lớp
        if user.is_mfa_enabled:
            mfa_temp_token = create_access_token(data={"sub": user.username, "scope": "mfa_pending"})
            return AuthResponse(
                message="Xác thực SSO thành công. Vui lòng nhập OTP để hoàn tất.",
                require_mfa=True, 
                temp_token=mfa_temp_token, 
                remember_cookie=None
            )

        access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
        
        return AuthResponse(
            message="Đăng nhập SSO thành công", 
            role=user.role.value,
            access_token=access_token, 
            token_type="bearer"
        )


    def verify_mfa(self, db: Session, request: MFAVerifyRequest) -> dict:
        try:
            # Giải mã cái temp_token từ bước login để biết là ai đang xin nhập OTP
            payload = verify_jwt_token(request.username) 
            # Chặn  hacker lấy JWT đắp vào đây
            if payload.get("scope") != "mfa_pending": 
                raise Exception()
            actual_username = payload.get("sub")
        except Exception:
            raise HTTPException(status_code=401, detail="Phiên xác thực OTP đã hết hạn hoặc không hợp lệ!")

        user = self.user_repo.get_by_username(db, actual_username)
        
        # Chặn ngay nếu tài khoản đã bị khóa 
        if not user or user.is_locked:
            raise HTTPException(status_code=401, detail="Tài khoản đã bị khóa do nhập sai OTP quá nhiều lần.")

        if not user.mfa_secret:
            raise HTTPException(status_code=400, detail="MFA chưa được thiết lập.")
            
        # Ném mã người dùng nhập và Secret key trong DB vào hàm check
        if verify_mfa_token(user.mfa_secret, request.otp_token):
            # Thành công thì clear số lần sai
            self.user_repo.update_failed_attempts(db, user, 0, False)
            user.is_mfa_enabled = True
            db.commit()
            
            # Đạt yêu cầu! Cấp JWT thật sự để vào hệ thống
            access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
            return {
                "message": "Xác thực MFA thành công!", 
                "session_id": str(uuid.uuid4()), 
                "access_token": access_token, 
                "token_type": "bearer", 
                "role": user.role.value
            }
            
        # Dùng Atomic Update để chặn Turbo Intruder bắn nát DB
        db.execute(
            update(User).where(User.id == user.id).values(
                failed_login_attempts=User.failed_login_attempts + 1,
                is_locked=(User.failed_login_attempts + 1 >= 5)
            )
        )
        db.commit()
        db.refresh(user) # Bắt Python tải lại dữ liệu mới nhất từ DB lên biến user
        
        # Kiểm tra xem đợt update vừa rồi có làm tài khoản bị khóa không
        if user.is_locked:
            raise HTTPException(status_code=401, detail="Tài khoản đã bị khóa bảo vệ do nhập sai OTP 5 lần!")
        else:
            raise HTTPException(status_code=401, detail=f"Mã OTP không chính xác. Bạn còn {5 - user.failed_login_attempts} lần thử.")


    # Các hàm phụ trợ bên dưới 
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

    def forgot_password(self, db: Session, request: ForgotPasswordRequest, http_request: Request) -> dict:
        # Tìm User theo Username hoặc Email
        user = db.query(User).filter((User.username == request.username) | (User.email == request.username)).first()
        
        # Dù có tìm thấy User hay không, vẫn trả về 1 câu thông báo y hệt nhau.
        if not user:
            return {"message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi an toàn."}
            
        import secrets
        from datetime import datetime, timedelta
        
        # Token siêu mạnh, không thể Brute-force
        reset_token = secrets.token_urlsafe(32)
        self.token_repo.create_token(db, user.id, reset_token, datetime.now() + timedelta(minutes=15))
        
        # Fix cứng Domain tĩnh từ cấu hình. 
        safe_domain = "127.0.0.1:8000" 
        secure_link = f"http://{safe_domain}/reset.html?token={reset_token}"
        
        return {
            "message": "Nếu tài khoản tồn tại, email khôi phục sẽ được gửi an toàn.", 
            "reset_link_demo": secure_link
        }

    def reset_password(self, db: Session, request: ResetPasswordRequest) -> dict:
        token_record = self.token_repo.get_token(db, request.token)
        
        # Kiểm tra token có tồn tại, còn hạn và chưa bị sử dụng hay không
        if not token_record or token_record.is_used or datetime.now() > token_record.expires_at:
            raise HTTPException(status_code=400, detail="Token không hợp lệ hoặc đã hết hạn.")
            
        # Truy vấn thẳng vào ID, bỏ vòng lặp for quét cả Database
        user = db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")
            
        # Cập nhật bằng thuật toán mạnh (Bcrypt) vào đúng cột secure
        user.password_hash_secure = hash_bcrypt(request.new_password)
        
        # VĐánh dấu Token đã sử dụng ngay lập tức
        self.token_repo.mark_used(db, token_record)
        db.commit()
        
        return {"message": "Mật khẩu đã được đặt lại thành công!"}

 