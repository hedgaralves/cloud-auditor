from sqlalchemy import Column, String, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

Base = declarative_base()

class Tenant(Base):
    __tablename__ = 'tenants'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    aws_account_id = Column(String, unique=True)
    scans = relationship("Scan", back_populates="tenant")

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'))
    timestamp = Column(DateTime, default=datetime.utcnow)
    score = Column(Float)
    findings = Column(JSON) # Guardaremos o snapshot do erro aqui
    tenant = relationship("Tenant", back_populates="scans")