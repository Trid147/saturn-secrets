import uuid
from sqlalchemy import Column, String
from database import Base

class Secret(Base):
    __tablename__ = 'secrets'

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    secret_text = Column(String, nullable=False)