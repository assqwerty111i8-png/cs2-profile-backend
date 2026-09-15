from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import relationship

from .database import Base


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

    user = relationship(
        "User",
        back_populates="profile",
    )


class Skin(Base):
    __tablename__ = "skins"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String, nullable=False)
    weapon = Column(String, nullable=False)
    rarity = Column(String, nullable=False)

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


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)

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

