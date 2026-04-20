import random
import time
from sqlalchemy.orm import Session
from src.config.database import SessionLocal, engine
from src.models.user import User, UserRole
from src.utils.hash_util import hash_md5, hash_bcrypt
from src.security.auth_provider import generate_mfa_secret
from src.config.settings import settings

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345", 
    "admin123", "admin@123", "password123", "000000", "P@ssword123"
]

def get_hashed(plain_text):
    if settings.AUTH_MODE == "secure":
        return hash_bcrypt(plain_text)
    return hash_md5(plain_text)

def seed_data():
    print(f"⏳ Đang kết nối Database... (Chế độ hiện tại: {settings.AUTH_MODE.upper()})")
    db: Session = SessionLocal()
    
    try:
        print("🧹 Đang làm sạch dữ liệu cũ...")
        db.query(User).delete()
        db.commit()

        print("🔑 Đang chuẩn bị các bản băm mật khẩu...")
        pass_hashes = {pwd: get_hashed(pwd) for pwd in COMMON_PASSWORDS}
        admin_pass_hash = get_hashed("admin123")
        
        users_to_insert = []
        
        print("🛡️ Đang tạo 5 tài khoản Admin...")
        for i in range(1, 6):
            admin = User(
                username=f"admin_{i}",
                email=f"admin_{i}@lab.com",
                password_hash=admin_pass_hash,
                role=UserRole.admin,  
                is_mfa_enabled=True,
                mfa_secret=generate_mfa_secret(),
                failed_login_attempts=0,
                is_locked=False
            )
            users_to_insert.append(admin)

        print("🎯 Đang tạo 10.000 tài khoản người dùng ảo...")
        start_time = time.time()
        for i in range(1, 10001):
            random_pass = random.choice(COMMON_PASSWORDS)
            user = User(
                username=f"victim_{i}",
                email=f"victim_{i}@lab.com",
                password_hash=pass_hashes[random_pass], 
                role=UserRole.user, 
                is_mfa_enabled=True, 
                mfa_secret=generate_mfa_secret(),
                failed_login_attempts=0,
                is_locked=False
            )
            users_to_insert.append(user)

        print("🚀 Đang đẩy dữ liệu vào CSDL...")
        db.bulk_save_objects(users_to_insert)
        db.commit()
        
        print(f"✅ Hoàn tất trong {time.time() - start_time:.2f} giây.")
        
    except Exception as e:
        print(f"❌ LỖI TRONG QUÁ TRÌNH SEED: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_data()