from pydantic import BaseModel
from typing import Optional

class UserProfileResponse(BaseModel):
    """
    Schema này dùng để lọc dữ liệu trước khi trả về.
    """
    id: int
    username: str
    email: Optional[str] = None
    role: str
    is_locked: bool
    
    class Config:
        from_attributes = True # Giúp Pydantic tự động đọc dữ liệu từ object SQLAlchemy