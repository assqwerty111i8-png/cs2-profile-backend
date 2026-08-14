from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    notes = relationship(
        "Note",
        back_populates="owner",
        cascade="all, delete-orphan",
    )


class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False)
    is_public = Column(Boolean, default=False, nullable=False)

    owner_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    owner = relationship(
        "User",
        back_populates="notes",
    )


class ShareToken(Base):
    __tablename__ = "share_tokens"

    id = Column(Integer, primary_key=True, index=True)

    # Храним НЕ сам токен, а его SHA-256
    token_hash = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    # К какой заметке относится ссылка
    note_id = Column(
        Integer,
        ForeignKey("notes.id"),
        nullable=False,
        index=True,
    )

    # Кто создал ссылку
    created_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    # Время окончания действия
    expires_at = Column(
        DateTime,
        nullable=False,
    )

    # Можно досрочно отозвать
    revoked = Column(
        Boolean,
        default=False,
        nullable=False,
    )