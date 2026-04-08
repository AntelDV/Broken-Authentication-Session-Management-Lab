import random
from sqlalchemy.orm import Session
from src.config.database import SessionLocal, engine
from src.models.user import User, UserRole
from src.utils.hash_util import hash_md5
from src.security.auth_provider import generate_mfa_secret

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345", 
    "admin123", "admin@123", "password123", "000000", "P@ssword123"
]

def seed_data():
    print("⏳ Đang kết nối Database và nạp 10.000 User...")
    
    db: Session = SessionLocal()
    
    try:
        print("🧹 Đang dọn dẹp vùng nhớ cũ...")
        db.query(User).delete()
        db.commit()

        users_to_insert = []
        
        print("🛡️ Đang tạo 5 Admin ...")
        for i in range(1, 6):
            admin = User(
                username=f"admin_{i}",
                email=f"admin_{i}@lab.com",
                password_hash=hash_md5("admin123"),
                role=UserRole.admin,  
                is_mfa_enabled=True,
                mfa_secret=generate_mfa_secret(),
                failed_login_attempts=0,
                is_locked=False
            )
            users_to_insert.append(admin)

        print("🎯 Đang tạo 10.000 User ...")
        for i in range(1, 10001):
            random_pass = random.choice(COMMON_PASSWORDS)
            
            user = User(
                username=f"victim_{i}",
                email=f"victim_{i}@lab.com",
                password_hash=hash_md5(random_pass), 
                role=UserRole.user, 
                is_mfa_enabled=True, 
                mfa_secret=generate_mfa_secret(),
                failed_login_attempts=0,
                is_locked=False
            )
            users_to_insert.append(user)

        print("🚀 Đang ghi hàng loạt xuống CSDL...")
        db.bulk_save_objects(users_to_insert)
        db.commit()
        
        
    except Exception as e:
        print(f"❌ Có lỗi xảy ra trong quá trình nạp dữ liệu: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_data()