from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
import secrets
from datetime import datetime, timedelta
from .database import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id')),
    Column('role_id', Integer, ForeignKey('role.id'))
)


class Role(Base):
    __tablename__ = 'role'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(200), nullable=True)

    def __repr__(self):
        return f"<Role {self.name}>"


class User(Base):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(120), nullable=True)

    roles = relationship('Role', secondary=user_roles, backref='users')

    reset_token = Column(String(120), nullable=True)
    token_expiration = Column(DateTime, nullable=True)
    token_revoked_at = Column(DateTime, default=datetime.utcnow)

    failed_attempts = Column(Integer, default=0, nullable=False)
    is_locked = Column(Boolean, default=False, nullable=False)
    lock_until = Column(DateTime, nullable=True)

    totp_secret = Column(String(32), nullable=True)
    is_totp_enabled = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_reset_token(self, db_session):
        self.reset_token = secrets.token_urlsafe(32)
        self.token_expiration = datetime.utcnow() + timedelta(minutes=30)
        db_session.commit()
        return self.reset_token

    def verify_reset_token(self, token):
        return self.reset_token == token and self.token_expiration and self.token_expiration > datetime.utcnow()


class ActivityLog(Base):
    __tablename__ = 'activity_log'

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    action = Column(String(255), nullable=False)
    target = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    actor = relationship('User', backref='activity_logs')


class Token(Base):
    __tablename__ = 'token'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    token = Column(String(120), nullable=False)
    expiration = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship('User', backref='tokens')