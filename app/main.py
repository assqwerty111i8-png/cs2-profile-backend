import asyncio
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from sqlalchemy import delete

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .database import Base, engine, SessionLocal
from . import models
from .models import RevokedToken
from .limiter import limiter


async def cleanup_revoked_tokens():
    while True:
        try:
            db = SessionLocal()

            try:
                deleted = (
                    db.query(RevokedToken)
                    .filter(
                        RevokedToken.expires_at
                        < datetime.utcnow()
                    )
                    .delete(
                        synchronize_session=False
                    )
                )

                db.commit()

                if deleted:
                    print(
                        f"Removed {deleted} expired revoked tokens"
                    )

            finally:
                db.close()

        except Exception as exc:
            print(
                f"RevokedToken cleanup error: {exc}"
            )

        await asyncio.sleep(300)  # каждые 5 минут


@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(
        cleanup_revoked_tokens()
    )

    try:
        yield
    finally:
        cleanup_task.cancel()

        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Secure CS2 Inventory API",
    version="1.0.0",
    lifespan=lifespan,
)


# ==========================================
# RATE LIMITING
# ==========================================

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
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
