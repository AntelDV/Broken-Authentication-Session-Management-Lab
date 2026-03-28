from sqlalchemy.orm import Session
from src.models.attack_log import AttackLog

class LogRepository:
    def log_attack(self, db: Session, ip: str, attack_type: str, request_data: str = ""):
        new_log = AttackLog(
            ip_address=ip,
            attack_type=attack_type,
            request_data=request_data
        )
        db.add(new_log)
        db.commit()