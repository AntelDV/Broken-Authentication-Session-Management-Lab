import os
import sys
import random
from sqlalchemy.orm import Session

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.config.database import SessionLocal
from src.models.user import User
from src.utils.hash_util import hash_md5

def seed_10000_users():
    db: Session = SessionLocal()
    print("🚀 Đang chuẩn bị tạo 10.000 Users giả lập...")

    common_passwords = ["123456", "password", "123456789", "12345", "admin123"]
    
    hashed_passwords = [hash_md5(p) for p in common_passwords]

    users_to_insert = []
    
    for i in range(1, 10001):
        random_hash = random.choice(hashed_passwords) 
        
        user = User(
            username=f"victim_{i}",
            email=f"victim_{i}@lab.com",
            password_hash=random_hash,
            role="user",
            is_locked=False
        )
        users_to_insert.append(user)
        
        if i % 2000 == 0:
            print(f"⏳ Đã chuẩn bị {i} users...")

    print("💾 Đang đẩy vào Database ... Chờ vài giây!")
    db.bulk_save_objects(users_to_insert) 
    db.commit()
    db.close()
    
    print("✅ Xong! Đã bơm thành công 10.000 user vào hệ thống.")

if __name__ == "__main__":
    seed_10000_users()