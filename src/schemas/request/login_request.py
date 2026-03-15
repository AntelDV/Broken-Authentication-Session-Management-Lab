# WORKFLOW: Định nghĩa cấu trúc dữ liệu bắt buộc Client phải gửi lên khi Login.
# CONCEPT: Dùng Pydantic để Validate (ví dụ: username không được rỗng, password tối thiểu 6 ký tự).
from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    """
    Lớp định nghĩa cấu trúc dữ liệu Frontend gửi lên khi Đăng nhập.
    Pydantic sẽ tự động kiểm tra lỗi (ví dụ: gửi thiếu password sẽ báo lỗi ngay).
    """
    # Bắt buộc phải có username, độ dài tối thiểu là 3 ký tự
    username: str = Field(..., min_length=3, description="Tên đăng nhập")
    
    # Bắt buộc phải có password, độ dài tối thiểu là 5 ký tự
    password: str = Field(..., min_length=5, description="Mật khẩu chưa mã hóa")