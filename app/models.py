from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
)

from sqlalchemy.orm import relationship

from .database import Base


# ==========================================
# USER
# ==========================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    username = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
    )

    hashed_password = Column(
        String,
        nullable=False,
    )

    failed_attempts = Column(
        Integer,
        default=0,
        nullable=False,
    )

    locked_until = Column(
        DateTime,
        nullable=True,
    )

    profile = relationship(
        "Profile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    skins = relationship(
        "Skin",
        back_populates="owner",
        cascade="all, delete-orphan",
    )

    matches = relationship(
        "Match",
        back_populates="user",
        cascade="all, delete-orphan",
    )


# ==========================================
# PROFILE
# ==========================================

class Profile(Base):
    __tablename__ = "profiles"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        unique=True,
        nullable=False,
    )

    level = Column(
        Integer,
        default=1,
        nullable=False,
    )

    kills = Column(
        Integer,
        default=0,
        nullable=False,
    )

    deaths = Column(
        Integer,
        default=0,
        nullable=False,
    )

    matches = Column(
        Integer,
        default=0,
        nullable=False,
    )

    inventory_count = Column(
        Integer,
        default=0,
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="profile",
    )


# ==========================================
# SKIN
# ==========================================

class Skin(Base):
    __tablename__ = "skins"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    name = Column(
        String,
        nullable=False,
    )

    weapon = Column(
        String,
        nullable=False,
    )

    rarity = Column(
        String,
        nullable=False,
    )

    owner_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    owner = relationship(
        "User",
        back_populates="skins",
    )


# ==========================================
# REVOKED TOKEN
# ==========================================

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    jti = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
    )

    expires_at = Column(
        DateTime,
        nullable=False,
    )


# ==========================================
# MATCH
# ==========================================

class Match(Base):
    __tablename__ = "matches"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    map_name = Column(
        String,
        nullable=False,
    )

    # Lifecycle:
    # pending -> in_progress -> finished
    # pending -> cancelled

    status = Column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    kills = Column(
        Integer,
        nullable=False,
        default=0,
    )

    deaths = Column(
        Integer,
        nullable=False,
        default=0,
    )

    won = Column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    user = relationship(
        "User",
        back_populates="matches",
    )
