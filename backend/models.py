from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, JSON, String

from database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    verdict = Column(String(50), nullable=False)
    risk_score = Column(Integer, nullable=False)
    reasons = Column(JSON, nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(Integer, nullable=False, index=True)

    severity = Column(String(20), nullable=False)

    title = Column(String(255), nullable=False)

    status = Column(
        String(20),
        nullable=False,
        default="open",
    )

    description = Column(String(1000), nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )