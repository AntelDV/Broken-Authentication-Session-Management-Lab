# WORKFLOW: Class Interface (Abstract) định nghĩa các hàm chuẩn (login, register).
# CONCEPT: Ép buộc cả 2 bản Vulnerable và Secure phải code chung một bộ hàm để Controller dễ gọi.
from abc import ABC, abstractmethod
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest
from src.schemas.response.auth_response import AuthResponse

from src.schemas.request.login_request import LoginRequest, MFAVerifyRequest, ForgotPasswordRequest, ResetPasswordRequest, GoogleSSORequest

class BaseAuthService(ABC):
    @abstractmethod
    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        pass
        
    @abstractmethod
    def setup_mfa(self, db: Session, username: str) -> dict:
        pass

    @abstractmethod
    def verify_mfa(self, db: Session, request: MFAVerifyRequest) -> dict:
        pass

    @abstractmethod
    def forgot_password(self, db: Session, request: ForgotPasswordRequest) -> dict:
        pass

    @abstractmethod
    def reset_password(self, db: Session, request: ResetPasswordRequest) -> dict:
        pass
    
    @abstractmethod
    def google_sso_login(self, db: Session, request: GoogleSSORequest) -> AuthResponse:
        pass