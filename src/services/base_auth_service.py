# WORKFLOW: Class Interface (Abstract) định nghĩa các hàm chuẩn (login, register).
# CONCEPT: Ép buộc cả 2 bản Vulnerable và Secure phải code chung một bộ hàm để Controller dễ gọi.
from abc import ABC, abstractmethod
from sqlalchemy.orm import Session
from src.schemas.request.login_request import LoginRequest
from src.schemas.response.auth_response import AuthResponse

class BaseAuthService(ABC):
    """
    Lớp trừu tượng định nghĩa các hàm
    """
    @abstractmethod
    def login(self, db: Session, request: LoginRequest) -> AuthResponse:
        pass