from fastapi import FastAPI, Request

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .database import Base, engine
from . import models
from .auth import decode_access_token


def get_user_id_from_jwt(request: Request) -> str:
    """
    Достаёт user_id напрямую из JWT.

    ВАЖНО:
    Здесь нельзя использовать Depends(),
    потому что SlowAPI вызывает key_func
    до FastAPI dependencies.
    """

    # Получаем Authorization header
    authorization = request.headers.get("Authorization")

    # Если JWT вообще нет — используем IP
    if not authorization:
        return request.client.host if request.client else "anonymous"

    # Ожидаем формат:
    # Authorization: Bearer <token>
    scheme, _, token = authorization.partition(" ")

    # Проверяем Bearer
    if scheme.lower() != "bearer" or not token:
        return request.client.host if request.client else "anonymous"

    # Декодируем и проверяем JWT
    payload = decode_access_token(token)

    # Если токен неправильный/просрочен
    if payload is None:
        return request.client.host if request.client else "anonymous"

    # Достаём user_id из payload
    user_id = payload.get("user_id")

    # Если user_id отсутствует
    if user_id is None:
        return request.client.host if request.client else "anonymous"

    # SlowAPI нужен строковый ключ
    return str(user_id)


# ==========================================
# SLOWAPI
# ==========================================

limiter = Limiter(
    key_func=get_user_id_from_jwt
)


# ==========================================
# FASTAPI
# ==========================================

app = FastAPI(
    title="Game Backend"
)

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)


# ==========================================
# DATABASE
# ==========================================

Base.metadata.create_all(
    bind=engine
)


# ==========================================
# ROUTES
# ==========================================

from .routes import router

app.include_router(router)