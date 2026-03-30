# WORKFLOW: Định nghĩa cấu trúc dữ liệu bắt buộc Client phải gửi lên khi Login.
# CONCEPT: Dùng Pydantic để Validate (ví dụ: username không được rỗng, password tối thiểu 6 ký tự).
from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, description="Tên đăng nhập")
    password: str = Field(..., min_length=5, description="Mật khẩu chưa mã hóa")
    remember_me: bool = Field(False, description="Tích vào ô Ghi nhớ đăng nhập")

class MFAVerifyRequest(BaseModel):
    username: str
    otp_token: str
    
class ForgotPasswordRequest(BaseModel):
    username: str
    
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    
class GoogleSSORequest(BaseModel):
    email: str = Field(..., description="Email mà Client báo cáo lên")
    google_id_token: str = Field(..., description="Mã Token do Google cấp")