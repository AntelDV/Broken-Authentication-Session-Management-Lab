from sqlalchemy.orm import Session
from src.models.password_reset_token import PasswordResetToken

class TokenRepository:
    def create_token(self, db: Session, user_id: int, token: str, expires_at):
        new_token = PasswordResetToken(user_id=user_id, token=token, expires_at=expires_at)
        db.add(new_token)
        db.commit()
        db.refresh(new_token)
        return new_token
    
    def get_token(self, db: Session, token: str):
        return db.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()
        
    def mark_used(self, db: Session, token_obj: PasswordResetToken):
        token_obj.is_used = True
        db.commit()