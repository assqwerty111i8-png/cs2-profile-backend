from typing import Optional
from datetime import datetime, timedelta
import hashlib
import secrets
import socket
import ipaddress
from urllib.parse import urlparse, urljoin

import httpx

from .pinned_transport import PinnedIPTransport

from pydantic import HttpUrl
from bs4 import BeautifulSoup

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

MAX_REDIRECTS = 5

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

def get_optional_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        HTTPBearer(auto_error=False)
    ),
    db: Session = Depends(get_db),
) -> User | None:
    if credentials is None:
        return None

    payload = decode_access_token(credentials.credentials)

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

def get_owned_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Note:
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

    return note

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

def validate_preview_url(url: str):
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Only http and https URLs are allowed",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL",
        )

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

addresses = socket.getaddrinfo(
    parsed.hostname,
    port,
    type=socket.SOCK_STREAM,
)

    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Unable to resolve hostname",
        )

    ips = {
        ipaddress.ip_address(address[4][0])
        for address in addresses
    }

    for ip in ips:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise HTTPException(
                status_code=403,
                detail="Destination address is not allowed",
            )

    return parsed, ips

MAX_REDIRECTS = 5
MAX_PREVIEW_SIZE = 1 * 1024 * 1024  # 1 MiB


@router.post("/preview")
async def preview(url: HttpUrl):
    current_url = str(url)

    for _ in range(MAX_REDIRECTS + 1):
        parsed, ips = validate_preview_url(current_url)

        response_status = None
        response_headers = {}
        response_body = bytearray()

        for ip in ips:
            try:
                transport = PinnedIPTransport(
                    verified_ip=str(ip)
                )

                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=10.0,
                    follow_redirects=False,
                ) as client:

                    async with client.stream(
                        "GET",
                        current_url,
                    ) as response:

                        response_status = response.status_code
                        response_headers = response.headers

                        if response_status in {
                            301,
                            302,
                            303,
                            307,
                            308,
                        }:
                            # Для redirect тело нам не нужно.
                            pass

                        else:
                            content_type = response.headers.get(
                                "content-type",
                                "",
                            ).lower()

                            if not (
                                content_type.startswith("text/html")
                                or content_type.startswith(
                                    "application/xhtml+xml"
                                )
                            ):
                                raise HTTPException(
                                    status_code=502,
                                    detail="Unsupported upstream content type",
                                )

                            async for chunk in response.aiter_bytes(
                                chunk_size=64 * 1024
                            ):
                                if (
                                    len(response_body)
                                    + len(chunk)
                                    > MAX_PREVIEW_SIZE
                                ):
                                    raise HTTPException(
                                        status_code=502,
                                        detail="Upstream response body is too large",
                                    )

                                response_body.extend(chunk)

                break

            except (
                httpx.ConnectError,
                httpx.ConnectTimeout,
            ):
                continue

        else:
            raise HTTPException(
                status_code=502,
                detail="Unable to connect to destination",
            )

        if response_status in {
            301,
            302,
            303,
            307,
            308,
        }:
            location = response_headers.get("location")

            if not location:
                break

            current_url = urljoin(
                current_url,
                location,
            )
            continue

        break

    else:
        raise HTTPException(
            status_code=400,
            detail="Too many redirects",
        )

    html = bytes(response_body).decode(
        "utf-8",
        errors="replace",
    )

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    title = (
        soup.title.string
        if soup.title
        else None
    )

    description_tag = soup.find(
        "meta",
        attrs={"name": "description"},
    )

    description = (
        description_tag.get("content")
        if description_tag
        else None
    )

    return {
        "title": title,
        "description": description,
    }

@router.patch(
    "/notes/{note_id}",
    response_model=NoteResponse,
)
def update_note(
    note_id: int,
    note: NoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    existing_note = (
        db.query(Note)
        .filter(
            Note.id == note_id,
            Note.owner_id == current_user.id,
        )
        .first()
    )

    if existing_note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

    if (
        note.title is None
        and note.content is None
        and note.is_public is None
    ):
        raise HTTPException(
            status_code=400,
            detail="No fields to update",
        )

    if note.title is not None:
        existing_note.title = note.title

    if note.content is not None:
        existing_note.content = note.content

    if note.is_public is not None:
        existing_note.is_public = note.is_public

    db.commit()
    db.refresh(existing_note)

    return existing_note  

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

@router.get(
    "/notes/{note_id}",
    response_model=NoteResponse,
)
def get_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    # 1. Анонимный пользователь:
    # может получить только публичную заметку.
    if current_user is None:
        note = (
            db.query(Note)
            .filter(
                Note.id == note_id,
                Note.is_public == True,
            )
            .first()
        )

    # 2. Авторизованный пользователь:
    # владелец может получить свою заметку,
    # а любой другой пользователь — только публичную.
    else:
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

    # Если заметка не найдена или доступ запрещён —
    # возвращаем одинаковый 404.
    if note is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found",
        )

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
def get_note_by_id(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    if current_user is None:
        note = (
            db.query(Note)
            .filter(
                Note.id == note_id,
                Note.is_public == True,
            )
            .first()
        )
    else:
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
    db: Session = Depends(get_db),
    note: Note = Depends(get_owned_note),
):
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
