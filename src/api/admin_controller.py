from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials # Bổ sung HTTPBearer
from sqlalchemy.orm import Session
from typing import List

from src.config.settings import settings
from src.config.database import get_db
from src.models.user import User
from src.schemas.response.user_profile_response import UserProfileResponse
from src.security.jwt_handler import verify_jwt_token

router = APIRouter(prefix="/api/admin", tags=["Admin (Modern JWT Auth)"])

security = HTTPBearer(auto_error=False)

@router.get("/users", response_model=List[UserProfileResponse])
def get_all_users(
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security) 
):
    if not credentials:
        raise HTTPException(
            status_code=401, 
            detail="Yêu cầu xác thực. Vui lòng cung cấp Bearer Token."
        )
        
    # Trích xuất chuỗi token từ Header
    token = credentials.credentials

    # Xác thực JWT Token
    payload = verify_jwt_token(token)
    username = payload.get("sub")
    user_role = payload.get("role")

    if not username:
        raise HTTPException(status_code=401, detail="Cấu trúc Token không hợp lệ.")

    # Kiểm tra phân quyền 
    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Truy cập bị từ chối! Yêu cầu quyền Quản trị viên."
        )

    # Nếu qua được khiên, trả về toàn bộ Database
    return db.query(User).all()