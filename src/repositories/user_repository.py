# WORKFLOW: Chứa các lệnh truy vấn DB thực tế (ví dụ: get_user_by_username).
# CONCEPT: Tách biệt query DB ra khỏi tầng Service để dễ thay đổi Database sau này.
from sqlalchemy.orm import Session
from src.models.user import User

class UserRepository:
    """
    Lớp xử lý các thao tác với cơ sở dữ liệu cho bảng users.
    """

    def get_by_username(self, db: Session, username: str):
        """
        Tìm kiếm người dùng theo username.
        """
        return db.query(User).filter(User.username == username).first()

    def create(self, db: Session, username: str, password_hash: str, email: str = None):
        """
        Tạo một bản ghi người dùng mới.
        """
        new_user = User(
            username=username,
            password_hash=password_hash,
            email=email
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user

    def update_failed_attempts(self, db: Session, user: User, attempts: int, is_locked: bool = False):
        """
        Cập nhật số lần đăng nhập sai và trạng thái khóa của tài khoản.
        """
        user.failed_login_attempts = attempts
        user.is_locked = is_locked
        db.commit()
        db.refresh(user)
        return user