from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.config.settings import settings

# Tùy chỉnh tham số kết nối cho SQLite 
connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}

# Cấu hình Connection Pool để chống sập Server khi demo Brute-force bằng Hydra
pool_kwargs = {}
if "mysql" in settings.DATABASE_URL:
    pool_kwargs = {
        "pool_size": 10,        # Giữ sẵn 10 kết nối thường trực
        "max_overflow": 20,     # Bơm thêm tối đa 20 kết nối khi bị spam request
        "pool_timeout": 30      # Đợi tối đa 30s nếu hết kết nối, tránh crash app
    }

# Khởi tạo engine kết nối
engine = create_engine(
    settings.DATABASE_URL, 
    connect_args=connect_args,
    **pool_kwargs
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """
    Hàm cung cấp session database cho mỗi request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()