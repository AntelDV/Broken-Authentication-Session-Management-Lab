# WORKFLOW: Định nghĩa dữ liệu trả về sau khi Login thành công.
# CONCEPT: Trả về Token hoặc SessionID, tuyệt đối không trả về thông tin nhạy cảm của User.
from pydantic import BaseModel

class AuthResponse(BaseModel):
    """
    Lớp định nghĩa cấu trúc dữ liệu Backend trả về khi đăng nhập thành công.
    """
    message: str
    session_id: str
    role: str