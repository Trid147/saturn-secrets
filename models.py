import uuid
from sqlalchemy import Column, DateTime, String, LargeBinary
from database import Base

class Secret(Base):
    __tablename__ = 'secrets'

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    secret_text = Column(LargeBinary, nullable=False)
    owner_username = Column(String, nullable=True, default=None)
    expires_at = Column(DateTime, nullable=True, default=None)
    whitelist = Column(String, nullable=True, default=None)
    blacklist = Column(String, nullable=True, default=None)

class User(Base):
    __tablename__ = 'user'

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)