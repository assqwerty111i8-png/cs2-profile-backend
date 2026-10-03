import asyncio
import logging

from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .database import Base, engine, SessionLocal
from . import models
from .models import RevokedToken, Match
from .limiter import limiter
from .routes import router


# ==========================================
# LOGGER
# ==========================================

logger = logging.getLogger(__name__)


# ==========================================
# CLEANUP REVOKED TOKENS
# ==========================================

async def cleanup_revoked_tokens():
    while True:
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
                logger.info(
                    "Removed %s expired revoked tokens",
                    deleted,
                )

        except Exception:
            db.rollback()

            logger.exception(
                "RevokedToken cleanup error"
            )

        finally:
            db.close()

        await asyncio.sleep(300)


# ==========================================
# CLEANUP PENDING MATCHES
# ==========================================

async def cleanup_pending_matches():
    while True:
        db = SessionLocal()

        try:
            cutoff = (
                datetime.utcnow()
                - timedelta(minutes=30)
            )

            updated = (
                db.query(Match)
                .filter(
                    Match.status == "pending",
                    Match.created_at < cutoff,
                )
                .update(
                    {
                        Match.status: "cancelled"
                    },
                    synchronize_session=False,
                )
            )

            db.commit()

            if updated:
                logger.info(
                    "Cancelled %s stale pending matches",
                    updated,
                )

        except Exception:
            db.rollback()

            logger.exception(
                "Pending match cleanup error"
            )

        finally:
            db.close()

        await asyncio.sleep(300)


# ==========================================
# LIFESPAN
# ==========================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    revoked_tokens_task = asyncio.create_task(
        cleanup_revoked_tokens()
    )

    pending_matches_task = asyncio.create_task(
        cleanup_pending_matches()
    )

    try:
        yield

    finally:
        revoked_tokens_task.cancel()
        pending_matches_task.cancel()

        await asyncio.gather(
            revoked_tokens_task,
            pending_matches_task,
            return_exceptions=True,
        )


# ==========================================
# APP
# ==========================================

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

app.include_router(router)
