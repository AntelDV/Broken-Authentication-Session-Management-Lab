import hashlib
from passlib.context import CryptContext

# Cấu hình Passlib để dùng Bcrypt cho bản Secure
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_md5(password: str) -> str:
    """Băm mật khẩu bằng MD5 (Cố tình làm yếu cho bản Vulnerable)"""
    return hashlib.md5(password.encode()).hexdigest()

def verify_md5(plain_password: str, hashed_password: str) -> bool:
    """Kiểm tra mật khẩu MD5"""
    return hash_md5(plain_password) == hashed_password

def hash_bcrypt(password: str) -> str:
    """Băm mật khẩu bằng Bcrypt có Salt tự động (Bản Secure)"""
    return pwd_context.hash(password)

def verify_bcrypt(plain_password: str, hashed_password: str) -> bool:
    """Kiểm tra mật khẩu Bcrypt"""
    return pwd_context.verify(plain_password, hashed_password)