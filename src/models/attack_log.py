from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from src.models.user import Base

class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String(45), index=True)
    attack_type = Column(String(50)) #  'Brute-force', 'Credential Stuffing'
    request_data = Column(Text, nullable=True)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())