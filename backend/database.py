from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

# Create database in the data folder
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ghost.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Profile(Base):
    __tablename__ = 'profiles'
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String)
    username = Column(String)
    phone = Column(String)
    notes = Column(Text)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # OSINT data fields
    breach_count = Column(Integer, default=0)
    social_media_json = Column(Text)  # Store as JSON string
    exposed_passwords = Column(Text)
    data_leaks = Column(Text)

class SocialMedia(Base):
    __tablename__ = 'social_media'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String, nullable=False)
    platform = Column(String)
    username = Column(String)
    url = Column(String)
    followers = Column(Integer)
    posts_count = Column(Integer)
    discovered_at = Column(DateTime, default=datetime.utcnow)

class Breach(Base):
    __tablename__ = 'breaches'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String, nullable=False)
    breach_name = Column(String)
    breach_date = Column(String)
    data_classes = Column(Text)  # What data was leaked
    discovered_at = Column(DateTime, default=datetime.utcnow)

class Device(Base):
    __tablename__ = 'devices'

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String)
    ip_address = Column(String)
    hostname = Column(String)
    device_type = Column(String)
    ports_open = Column(Text)
    vulnerabilities = Column(Text)
    location = Column(String)
    discovered_at = Column(DateTime, default=datetime.utcnow)

class BaitToken(Base):
    __tablename__ = 'bait_tokens'

    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier = Column(String, unique=True, nullable=False)  # format: "bait_abc123"
    bait_type = Column(String)  # aws_key, stripe_token, database, ssh_key, github_token, slack_token
    token_value = Column(Text)  # JSON serialized fake credential
    seeded_at = Column(DateTime, default=datetime.utcnow)
    seeded_location = Column(String)  # URL where posted (e.g., Pastebin URL)
    first_access = Column(DateTime, nullable=True)
    access_count = Column(Integer, default=0)
    last_access = Column(DateTime, nullable=True)
    status = Column(String, default='active')  # active, triggered, expired, revoked

    # Relationship to access logs
    accesses = relationship('BaitAccess', back_populates='bait_token', cascade='all, delete-orphan')

class BaitAccess(Base):
    __tablename__ = 'bait_accesses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    bait_id = Column(Integer, ForeignKey('bait_tokens.id'), nullable=False)
    accessed_at = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    user_agent = Column(String)
    request_type = Column(String)  # http, api, ssh, database
    request_headers = Column(Text)  # JSON serialized headers
    request_body = Column(Text)  # JSON serialized request data
    fingerprint = Column(Text)  # scanner fingerprint analysis
    geolocation = Column(String)  # format: "City, Country"
    threat_level = Column(String, default='medium')  # low, medium, high, critical
    notes = Column(Text)  # additional analysis notes

    # Relationship to bait token
    bait_token = relationship('BaitToken', back_populates='accesses')

def init_db():
    """Initialize the database and create all tables"""
    Base.metadata.create_all(engine)
    print(f"Database initialized at: {DB_PATH}")

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass

# Initialize database on import
init_db()