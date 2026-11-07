import uuid
from sqlalchemy import Column, String, LargeBinary, null
from database import Base

class Secret(Base):
    __tablename__ = 'secrets'

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    secret_text = Column(LargeBinary, nullable=False)

class User(Base):
    __tablename__ = 'user'

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)