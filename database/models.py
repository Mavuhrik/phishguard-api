from sqlalchemy import String, Integer, DateTime
from datetime import datetime, timezone
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(2048), nullable = False)
    domain: Mapped[str] = mapped_column(String(255))
    risk_score: Mapped[int] = mapped_column()
    risk_level: Mapped[str] = mapped_column(String(20))
    created_at : Mapped[datetime] = mapped_column(DateTime(timezone = True),
     default = lambda : datetime.now(timezone.utc))
        
        
        