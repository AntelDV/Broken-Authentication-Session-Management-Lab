# WORKFLOW: Ánh xạ thực thể User thành bảng trong Database (SQLAlchemy).
# CÁC TRƯỜNG DỰ KIẾN: id, username, password_hash, is_active, failed_login_attempts (để hỗ trợ khóa tài khoản).
import enum
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Sử dụng Enum cho phân quyền
class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    
    # Cột chứa hash 
    password_hash = Column(String(255), nullable=False) 
    
    full_name = Column(String(100))
    email = Column(String(100), unique=True, index=True)
    role = Column(Enum(UserRole), default=UserRole.user)

    # --- CÁC TRƯỜNG PHỤC VỤ PHÒNG THỦ BRUTE-FORCE (RATE LIMITING) ---
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime(timezone=True), nullable=True)
    is_locked = Column(Boolean, default=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # --- CÁC TRƯỜNG TÍCH HỢP BẢO MẬT 2 LỚP (MFA) ---
    mfa_secret = Column(String(32), nullable=True)
    is_mfa_enabled = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}', is_locked={self.is_locked})>"