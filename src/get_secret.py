from src.config.database import SessionLocal
from src.models.user import User

db = SessionLocal()
admins = db.query(User).filter(User.username.like("admin_%")).all()

print("\n" + "="*50)
print("🔑 KHÓA BÍ MẬT CHO AUTHENTICATOR (MFA)")
print("="*50)
for admin in admins:
    print(f"👤 Tài khoản : {admin.email}")
    print(f"🤫 Mã Secret : {admin.mfa_secret}")
    print("-" * 50)