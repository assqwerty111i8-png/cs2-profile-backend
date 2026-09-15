from fastapi import FastAPI

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .database import Base, engine
from . import models

from .limiter import limiter


app = FastAPI(
    title="Secure CS2 Inventory API",
    version="1.0.0",
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
