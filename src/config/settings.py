# WORKFLOW: Quản lý toàn bộ cấu hình hệ thống một cách tập trung.
# CONCEPT: Dùng pydantic_settings để tự động map các biến từ file .env vào class Settings.
# ĐIỂM NEO: Biến AUTH_MODE là "công tắc" thần thánh để chúng ta chuyển đổi kịch bản demo.
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "Auth Security Lab"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    AUTH_MODE: str = os.getenv("AUTH_MODE", "vulnerable") 
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./lab_database.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "default_secret")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    class Config:
        env_file = ".env"

settings = Settings()
