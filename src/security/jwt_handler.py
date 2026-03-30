from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status
from src.config.settings import settings

def create_access_token(data: dict):
    """Sinh Token chuẩn mực với thuật toán HS256"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    # Ký bằng SECRET_KEY lấy từ biến môi trường
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_jwt_token(token: str):
    """Hàm xác thực Token (Cố tình chứa lỗi ở bản Vulnerable)"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Không thể xác thực thông tin xác thực (Invalid Token)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if settings.AUTH_MODE == "vulnerable":
            # CVE-2015-9256 Chấp nhận thuật toán "none".
            unverified_header = jwt.get_unverified_header(token)
            
            if unverified_header.get("alg").lower() == "none":
                return jwt.get_unverified_claims(token)
            
            # Nếu nó không xài "none", vẫn verify bình thường
            return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
        else:
            # Dù Header có là 'none' hay gì đi nữa, hàm decode sẽ ném ra lỗi.
            return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
    except JWTError:
        raise credentials_exception