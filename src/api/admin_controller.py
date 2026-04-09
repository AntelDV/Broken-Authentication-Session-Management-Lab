from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from src.config.settings import settings
from src.config.database import get_db
from src.models.user import User
from src.schemas.response.user_profile_response import UserProfileResponse
from src.security.jwt_handler import verify_jwt_token

router = APIRouter(prefix="/api/admin", tags=["Admin (Modern JWT Auth)"])

@router.get("/users", response_model=List[UserProfileResponse])
def get_all_users(
    request: Request,
    db: Session = Depends(get_db)
):
    # Tìm Token trên Header 
    auth_header = request.headers.get("Authorization")
    token = None
    
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        # Nếu Header không có, tự động lục tìm trong Cookie 
        token = request.cookies.get("auth_session_id")

    # Chặn ngay nếu không cung cấp vé qua trạm
    if not token:
        raise HTTPException(
            status_code=401, 
            detail="Yêu cầu xác thực. Không tìm thấy Token trong Header hoặc Cookie."
        )
        
    try:
        # Đưa Token vào máy chém JWT để giải mã
        payload = verify_jwt_token(token)
        username = payload.get("sub")
        user_role = payload.get("role")
    except Exception:
        raise HTTPException(status_code=401, detail="Cấu trúc Token không hợp lệ hoặc đã hết hạn.")

    # Kiểm tra phân quyền - Chỉ Admin mới được đi tiếp
    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Truy cập bị từ chối! Yêu cầu quyền Quản trị viên."
        )

    # Nếu qua được khiên bảo vệ, trả về toàn bộ dữ liệu người dùng
    return db.query(User).all()