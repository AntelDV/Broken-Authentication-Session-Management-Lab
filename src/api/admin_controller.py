from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from src.config.settings import settings
from src.config.database import get_db
from src.models.user import User, UserSession
from src.schemas.response.user_profile_response import UserProfileResponse
from src.security.jwt_handler import verify_jwt_token
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(prefix="/api/admin", tags=["Admin (Modern JWT Auth)"])

#@router.get("/users", response_model=List[UserProfileResponse])
@router.get("/users")
def get_all_users(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("auth_session_id")
    
    if not session_id:
        raise HTTPException(status_code=401, detail="Không tìm thấy phiên đăng nhập. Vui lòng login lại.")
        
    # Truy vấn trạng thái Stateful dưới Database
    active_session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if not active_session:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập không tồn tại hoặc đã bị thu hồi!")
    
    tz_vn = timezone(timedelta(hours=7))
    now_vn = datetime.now(tz_vn).replace(tzinfo=None)
        
    # Kiểm tra thời hạn hết hạn của phiên
    if active_session.expires_at < datetime.now():
        db.query(UserSession).filter(UserSession.session_id == session_id).delete()
        db.commit()
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn sử dụng.")
        
    user = db.query(User).filter(User.id == active_session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Người dùng không tồn tại.")

    if settings.AUTH_MODE == "secure":
        current_ip = request.client.host
        current_ua = request.headers.get("user-agent")
        if active_session.ip_address != current_ip or active_session.user_agent != current_ua:
            raise HTTPException(status_code=401, detail="Phát hiện hành vi chiếm đoạt phiên từ thiết bị lạ!")

    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Từ chối truy cập. Yêu cầu quyền Quản trị viên.")

    users_list = db.query(User).all()
    return [{"username": u.username, "email": u.email, "role": u.role, "is_mfa_enabled": u.is_mfa_enabled} for u in users_list]


class ModeToggleRequest(BaseModel):
    mode: str

@router.post("/switch-mode")
def toggle_auth_mode(request: ModeToggleRequest):
    if request.mode not in ["secure", "vulnerable"]:
        raise HTTPException(status_code=400, detail="Chế độ không hợp lệ!")
    
    settings.AUTH_MODE = request.mode
    
    print("\n" + "="*50)
    print(f"✅ [SYSTEM] SERVER ĐANG CHẠY CHẾ ĐỘ: {request.mode.upper()}")
    print("="*50 + "\n")
    
    return {
        "message": f"Đã chuyển đổi Server sang chế độ: {request.mode.upper()}",
        "current_mode": settings.AUTH_MODE
    }