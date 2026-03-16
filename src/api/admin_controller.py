# WORKFLOW: Các API chỉ dành cho Admin. 
# MỤC ĐÍCH: Dùng để test tính năng phân quyền hoặc biểu diễn lỗi cướp phiên (Hijacking) rồi truy cập trái phép.

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from src.config.settings import settings
from src.config.database import get_db
from src.models.user import User
from src.schemas.response.user_profile_response import UserProfileResponse

router = APIRouter(prefix="/api/admin", tags=["Admin (Broken Access Control)"])

@router.get("/users", response_model=List[UserProfileResponse])
def get_all_users(
    # Bắt buộc Client phải gửi Session ID qua Header để chứng minh đã đăng nhập
    x_session_id: str = Header(None, description="Session ID lấy từ lúc Login"),
    db: Session = Depends(get_db)
):
    if not x_session_id:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập (Thiếu Session ID)")

    # TRÍCH XUẤT THÔNG TIN TỪ SESSION 
    # Vì ở bản Vulnerable ta tạo session có dạng: "session_of_tenuser_static"
    username = ""
    if x_session_id.startswith("session_of_") and x_session_id.endswith("_static"):
        username = x_session_id.replace("session_of_", "").replace("_static", "")
    else:
        # Ở bản Secure, Session ID là chuỗi UUID ngẫu nhiên.
        # Đáng lý phải soi DB để tìm, nhưng để demo gọn ta chặn luôn ở đây.
        raise HTTPException(status_code=401, detail="Session không hợp lệ hoặc đã hết hạn (Secure Mode)")

    # Lấy thông tin user đang gửi Request
    current_user = db.query(User).filter(User.username == username).first()
    if not current_user:
        raise HTTPException(status_code=401, detail="User không tồn tại")

    # KIỂM TRA PHÂN QUYỀN 
    if settings.AUTH_MODE == "vulnerable":
        # Chỉ cần có tài khoản (đã login) là cho xem hết!
        # Hoàn toàn bỏ qua việc kiểm tra: current_user.role == "admin"
        pass
    else:
        # Phải soi đúng Role mới cho vào!
        if current_user.role.value != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Truy cập bị từ chối! Bạn không có quyền Quản trị viên."
            )

    
    # Lấy toàn bộ người dùng trong hệ thống
    all_users = db.query(User).all()
    return all_users