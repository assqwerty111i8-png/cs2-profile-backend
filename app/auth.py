import os

from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv

import uuid

from jose import JWTError, jwt
from passlib.context import CryptContext


load_dotenv(
    Path(__file__).parent.parent / ".env"
)


SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured"
    )


ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    return pwd_context.verify(
        password,
        hashed_password,
    )


def create_access_token(data: dict) -> str:
    to_encode = data.copy()

    expire = (
        datetime.utcnow()
        + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    to_encode.update({
        "exp": expire,
        "jti": str(uuid.uuid4()),
    })

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str):
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

    except JWTError:
        return None
