from typing import Optional
from datetime import datetime, timedelta
import hashlib
import secrets

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Query,
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
)
from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from .database import get_db
from .models import User, Note, ShareToken
from .schemas import (
    UserCreate,
    UserLogin,
    UserResponse,
    NoteCreate,
    NoteUpdate,
    NoteResponse,
    ShareTokenResponse,
)
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from .main import limiter

router = APIRouter()

security = HTTPBearer()


@router.post("/register", response_model=UserResponse)
def register(
    user: UserCreate,
    db: Session = Depends(get_db),
):
    existing = (
        db.query(User)
        .filter(User.username == user.username)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username already exists",
        )

    new_user = User(
        username=user.username,
        hashed_password=hash_password(user.password),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    user: UserLogin,
    db: Session = Depends(get_db),
):
    db_user = (
        db.query(User)
        .filter(User.username == user.username)
        .first()
    )

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    # Проверяем блокировку аккаунта
    if (
        db_user.locked_until is not None
        and db_user.locked_until > datetime.utcnow()
    ):
        raise HTTPException(
            status_code=429,
            detail="Account is temporarily locked",
        )

    # Проверяем пароль
    if not verify_password(
        user.password,
        db_user.hashed_password,
    ):
        db_user.failed_attempts += 1

        if db_user.failed_attempts >= 10:
            db_user.locked_until = (
                datetime.utcnow()
                + timedelta(minutes=15)
            )

        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    # Успешный вход
    db_user.failed_attempts = 0
    db_user.locked_until = None
    db.commit()

    access_token = create_access_token(
        {
            "sub": db_user.username,
            "user_id": db_user.id,
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:

    token = credentials.credentials

    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    user_id = payload.get("user_id")

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload",
        )

    current_user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )

    return current_user

@router.get("/me", response_model=UserResponse)
def me(
    current_user: User = Depends(get_current_user),
):
    return current_user


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    if user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Access denied",
        )

    return current_user


@router.post(
    "/notes",
    response_model=NoteResponse,
)
@limiter.limit("20/minute")
def create_note(
    request: Request,
    note: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    new_note = Note(
        title=note.title,
        content=note.content,
        is_public=note.is_public,
        created_at=datetime.utcnow(),
        owner_id=current_user.id,
    )

    db.add(new_note)
    db.commit()
    db.refresh(new_note)

    return new_note

@router.post(
    "/notes/{note_id}/share",
    response_model=ShareTokenResponse,
)
@limiter.limit("10/minute")
def create_share_token(
    note_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Только владелец может создать ссылку
    note = (
        db.query(Note)
        .filter(
            Note.id == note_id,
            Note.owner_id == current_user.id,
        )
        .first()
    )

    if note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    # Генерируем криптографически случайный токен
    raw_token = secrets.token_urlsafe(32)

    # В БД сохраняем только хеш
    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    # Ссылка действует 1 час
    expires_at = datetime.utcnow() + timedelta(hours=1)

    share_token = ShareToken(
        token_hash=token_hash,
        note_id=note.id,
        created_by=current_user.id,
        expires_at=expires_at,
        revoked=False,
    )

    db.add(share_token)
    db.commit()

    return {
        "token": raw_token,
        "note_id": note.id,
        "expires_at": expires_at,
    }

@router.get(
    "/shared-notes/{note_id}",
    response_model=NoteResponse,
)
def get_shared_note(
    note_id: int,
    token: str = Query(..., min_length=20),
    db: Session = Depends(get_db),
):
    # Хешируем токен из запроса
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    # Ищем токен, привязанный именно к этой заметке
    share_token = (
        db.query(ShareToken)
        .filter(
            ShareToken.token_hash == token_hash,
            ShareToken.note_id == note_id,
        )
        .first()
    )

    # Токен не найден или принадлежит другой заметке
    if share_token is None:
        raise HTTPException(
            status_code=404,
            detail="Share link not found",
        )

    # Токен отозван
    if share_token.revoked:
        raise HTTPException(
            status_code=403,
            detail="Share link revoked",
        )

    # Токен истёк
    if share_token.expires_at <= datetime.utcnow():
        raise HTTPException(
            status_code=403,
            detail="Share link expired",
        )

    # Получаем заметку, к которой привязан токен
    note = (
        db.query(Note)
        .filter(
            Note.id == share_token.note_id,
        )
        .first()
    )

    if note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    return note

@router.put(
    "/notes/{note_id}",
    response_model=NoteResponse,
)
def update_note(
    note_id: int,
    note_update: NoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Ищем заметку только среди заметок
    # текущего пользователя
    note = (
        db.query(Note)
        .filter(
            Note.id == note_id,
            Note.owner_id == current_user.id,
        )
        .first()
    )

    # Если заметка не существует
    # или принадлежит другому пользователю,
    # возвращаем одинаковый ответ
    if note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    # Обновляем title, если его передали
    if note_update.title is not None:
        note.title = note_update.title

    # Обновляем content, если его передали
    if note_update.content is not None:
        note.content = note_update.content

    db.commit()
    db.refresh(note)

    return note


# ==========================================
# МОИ ЗАМЕТКИ
# ==========================================

@router.get(
    "/notes",
    response_model=list[NoteResponse],
)
def get_my_notes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    notes = (
        db.query(Note)
        .filter(Note.owner_id == current_user.id)
        .order_by(Note.created_at.desc())
        .all()
    )

    return notes


# ==========================================
# ПОИСК ЗАМЕТОК
# ВАЖНО: этот маршрут должен быть
# ПЕРЕД /notes/{note_id}
# ==========================================

@router.get(
    "/notes/search",
    response_model=list[NoteResponse],
)
@limiter.limit("30/minute")
def search_notes(
    request: Request,
    title: str = Query(
        ...,
        min_length=1,
        max_length=100,
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Экранируем специальные символы LIKE
    safe_title = (
        title
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )

    query = text("""
        SELECT id, title, content, created_at, is_public, owner_id
        FROM notes
        WHERE title LIKE :title ESCAPE '\'
        AND (
            owner_id = :user_id
            OR is_public = 1
        )
        ORDER BY created_at DESC
    """)

    result = db.execute(
        query,
        {
            "title": f"%{safe_title}%",
            "user_id": current_user.id,
        },
    )

    return [dict(row._mapping) for row in result]


# ==========================================
# ПОЛУЧЕНИЕ ОДНОЙ ЗАМЕТКИ
# ВАЖНО: этот маршрут после /notes/search
# ==========================================

@router.get(
    "/notes/{note_id}",
    response_model=NoteResponse,
)
def get_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    note = (
        db.query(Note)
        .filter(
            Note.id == note_id,
            or_(
                Note.owner_id == current_user.id,
                Note.is_public == True,
            ),
        )
        .first()
    )

    if note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    return note

@router.delete("/notes/{note_id}", status_code=204)
def delete_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    note = (
        db.query(Note)
        .filter(
            Note.id == note_id,
            Note.owner_id == current_user.id
        )
        .first()
    )

    if note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    db.delete(note)
    db.commit()

    return None

@router.delete(
    "/notes/{note_id}/share",
    status_code=204,
)
@limiter.limit("10/minute")
def revoke_share_token(
    note_id: int,
    request: Request,
    token: str = Query(..., min_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Хешируем переданный токен
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    # Одним запросом проверяем сразу всё:
    # 1. токен существует
    # 2. токен относится к этой заметке
    # 3. текущий пользователь является владельцем заметки
    share_token = (
        db.query(ShareToken)
        .join(Note, ShareToken.note_id == Note.id)
        .filter(
            ShareToken.token_hash == token_hash,
            ShareToken.note_id == note_id,
            Note.owner_id == current_user.id,
        )
        .first()
    )

    if share_token is None:
        raise HTTPException(
            status_code=404,
            detail="Share link not found",
        )

    # Отзываем токен
    share_token.revoked = True

    db.commit()

    return None