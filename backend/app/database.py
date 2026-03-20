from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./iec62443.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    fr_id = Column(String)        # ej. "FR1", "FR2"...
    sr_id = Column(String)        # ej. "SR1.1", "SR1.2"...
    description = Column(String)
    status = Column(String)       # "PASS", "FAIL", "WARNING"
    details = Column(String)
    sl_level = Column(Integer)    # Nivel SL evaluado (1-4)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()