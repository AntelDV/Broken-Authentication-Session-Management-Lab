import enum
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from sqlalchemy import ForeignKey, Text


Base = declarative_base()

# Sử dụng Enum cho phân quyền
class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    
    # Đã tách thành 2 cột Hash riêng biệt để chạy song song 2 chế độ
    password_hash_vuln = Column(String(32), nullable=False) 
    password_hash_secure = Column(String(255), nullable=False) 
    
    full_name = Column(String(100))
    email = Column(String(100), unique=True, index=True)
    role = Column(Enum(UserRole), default=UserRole.user)

    # --- RATE LIMITING ---
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime(timezone=True), nullable=True)
    is_locked = Column(Boolean, default=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # ---  2 LỚP (MFA) ---
    mfa_secret = Column(String(32), nullable=True)
    is_mfa_enabled = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}', is_locked={self.is_locked})>"
    
    
class UserSession(Base):
    __tablename__ = "sessions"

    session_id = Column(String(255), primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    user_agent = Column(Text)
    ip_address = Column(String(45))
    
    issued_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime, nullable=False)