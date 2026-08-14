from datetime import datetime

from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


# ==========================================
# ЗАМЕТКИ
# ==========================================

class NoteCreate(BaseModel):
    title: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )
    content: str
    is_public: bool = False


class NoteUpdate(BaseModel):
    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    content: str | None = None


class NoteResponse(BaseModel):
    id: int
    title: str
    content: str
    created_at: datetime
    is_public: bool
    owner_id: int

    class Config:
        from_attributes = True


# ==========================================
# ВРЕМЕННЫЙ ДОСТУП
# ==========================================

class ShareTokenResponse(BaseModel):
    token: str
    note_id: int
    expires_at: datetime