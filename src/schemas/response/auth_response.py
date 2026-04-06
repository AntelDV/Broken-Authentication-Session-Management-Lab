
from pydantic import BaseModel
from typing import Optional

class AuthResponse(BaseModel):
    message: str
    session_id: Optional[str] = None
    role: Optional[str] = None
    require_mfa: bool = False
    temp_token: Optional[str] = None
    remember_cookie: Optional[str] = None
    #  JWT 
    access_token: Optional[str] = None  
    token_type: Optional[str] = None