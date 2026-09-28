from datetime import datetime, timedelta

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
)

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from .database import get_db

from .models import (
    User,
    Profile,
    Skin,
    RevokedToken,
)

from .schemas import (
    UserCreate,
    UserLogin,
    UserResponse,
    TokenResponse,
    ProfileResponse,
    PublicProfileResponse,
    SkinCreate,
    SkinTransfer,
    SkinResponse,
    LeaderboardEntry,
)


from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)

from .limiter import limiter


router = APIRouter()

security = HTTPBearer()


# ==========================================
# CURRENT USER
# ==========================================

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

    jti = payload.get("jti")

    if jti is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload",
        )

    # Проверяем blacklist
    revoked_token = (
        db.query(RevokedToken)
        .filter(RevokedToken.jti == jti)
        .first()
    )

    if revoked_token is not None:
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
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

# ==========================================
# AUTH
# ==========================================

@router.post(
    "/auth/register",
    response_model=UserResponse,
)
@limiter.limit("5/minute")
def register(
    request: Request,
    user: UserCreate,
    db: Session = Depends(get_db),
):
    new_user = User(
        username=user.username,
        hashed_password=hash_password(user.password),
    )

    db.add(new_user)

    try:
        # Здесь БД проверяет UNIQUE(username)
        db.flush()

        profile = Profile(
            user_id=new_user.id,
            level=1,
            kills=0,
            deaths=0,
            matches=0,
        )

        db.add(profile)

        db.commit()
        db.refresh(new_user)

        return new_user

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail="Username already exists",
        )


@router.post(
    "/auth/login",
    response_model=TokenResponse,
)
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

    if (
        db_user.locked_until is not None
        and db_user.locked_until > datetime.utcnow()
    ):
        raise HTTPException(
            status_code=429,
            detail="Account is temporarily locked",
        )

    # Неверный пароль
    if not verify_password(
        user.password,
        db_user.hashed_password,
    ):
        now = datetime.utcnow()
        lock_time = now + timedelta(minutes=15)

        db.query(User).filter(
            User.id == db_user.id
        ).update(
            {
                User.failed_attempts:
                    User.failed_attempts + 1,

                User.locked_until: case(
                    (
                        User.failed_attempts + 1 >= 10,
                        lock_time,
                    ),
                    else_=User.locked_until,
                ),
            },
            synchronize_session=False,
        )

        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    # Успешный вход — атомарно сбрасываем счётчик
    db.query(User).filter(
        User.id == db_user.id
    ).update(
        {
            User.failed_attempts: 0,
            User.locked_until: None,
        },
        synchronize_session=False,
    )

    db.commit()

    access_token = create_access_token({
        "sub": db_user.username,
        "user_id": db_user.id,
    })

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.post("/auth/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    jti = payload.get("jti")
    exp = payload.get("exp")

    if jti is None or exp is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload",
        )

    existing_token = (
        db.query(RevokedToken)
        .filter(RevokedToken.jti == jti)
        .first()
    )

    if existing_token is None:
        try:
            db.add(
                RevokedToken(
                    jti=jti,
                    expires_at=datetime.fromtimestamp(exp),
                )
            )

            db.commit()

        except IntegrityError:
            db.rollback()

    return {
        "detail": "Successfully logged out"
    }


# ==========================================
# USER
# ==========================================

@router.get(
    "/users/me",
    response_model=UserResponse,
)
def get_me(
    current_user: User = Depends(
        get_current_user
    ),
):
    return current_user

# =========================================
# PROFILE
# ==========================================

@router.get(
    "/profile",
    response_model=ProfileResponse,
)
def get_profile(
    current_user: User = Depends(
        get_current_user
    ),
):

    return current_user.profile

@router.get("/profile", response_model=ProfileResponse)
def get_profile(
    current_user: User = Depends(get_current_user),
):
    return current_user.profile


@router.get(
    "/users/{user_id}/profile",
    response_model=PublicProfileResponse,
)
def get_public_profile(
    user_id: int,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if user is None or user.profile is None:
        raise HTTPException(
            status_code=404,
            detail="Profile not found",
        )

    return {
        "username": user.username,
        "level": user.profile.level,
        "kills": user.profile.kills,
        "deaths": user.profile.deaths,
        "matches": user.profile.matches,
    }

def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return current_user


# ==========================================
# INVENTORY
# ==========================================

@router.get(
    "/inventory",
    response_model=list[SkinResponse],
)
def get_inventory(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Skin)
        .filter(
            Skin.owner_id == current_user.id
        )
        .all()
    )


# ==========================================
# OWNED SKIN DEPENDENCY
# ==========================================

def get_owned_skin(
    skin_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Skin:

    skin = (
        db.query(Skin)
        .filter(
            Skin.id == skin_id,
            Skin.owner_id == current_user.id,
        )
        .first()
    )

    if skin is None:
        raise HTTPException(
            status_code=404,
            detail="Skin not found",
        )

    return skin


# ==========================================
# GET ONE SKIN
# ==========================================

@router.get(
    "/inventory/{skin_id}",
    response_model=SkinResponse,
)
def get_skin(
    skin: Skin = Depends(get_owned_skin),
):
    return skin


# ==========================================
# USER INVENTORY
# ==========================================

@router.get(
    "/users/{user_id}/inventory",
    response_model=list[SkinResponse],
)
def get_user_inventory(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if user_id != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="Inventory not found",
        )

    return (
        db.query(Skin)
        .filter(
            Skin.owner_id == current_user.id
        )
        .all()
    )


# ==========================================
# ADD SKIN
# ==========================================

@router.post(
    "/inventory",
    response_model=SkinResponse,
)
@limiter.limit("20/minute")
def add_skin(
    request: Request,
    skin_data: SkinCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    # Блокируем строку пользователя до конца транзакции.
    # Другой add_skin для этого же user_id будет ждать здесь.
    user = (
        db.query(User)
        .filter(User.id == current_user.id)
        .with_for_update()
        .one()
    )

    # Источник истины — реальная таблица Skin
    skin_count = (
        db.query(Skin)
        .filter(Skin.owner_id == user.id)
        .count()
    )

    if skin_count >= 1000:
        raise HTTPException(
            status_code=400,
            detail="Inventory limit reached",
        )

    skin = Skin(
        name=skin_data.name,
        weapon=skin_data.weapon,
        rarity=skin_data.rarity,
        owner_id=user.id,
    )

    db.add(skin)
    db.commit()
    db.refresh(skin)

    return skin


@router.post(
    "/inventory/{skin_id}/transfer",
    response_model=SkinResponse,
)
@limiter.limit("100/minute")  # временно для теста
def transfer_skin(
    request: Request,
    skin_id: int,
    transfer_data: SkinTransfer,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if transfer_data.target_user_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot transfer skin to yourself",
        )

    target_user = (
        db.query(User)
        .filter(
            User.id == transfer_data.target_user_id
        )
        .first()
    )

    if target_user is None:
        raise HTTPException(
            status_code=404,
            detail="Target user not found",
        )

    # АТОМАРНАЯ передача
    updated = (
        db.query(Skin)
        .filter(
            Skin.id == skin_id,
            Skin.owner_id == current_user.id,
        )
        .update(
            {
                Skin.owner_id: target_user.id
            },
            synchronize_session=False,
        )
    )

    if updated == 0:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail="Skin not found or already transferred",
        )

    db.commit()

    skin = (
        db.query(Skin)
        .filter(Skin.id == skin_id)
        .first()
    )

    return skin




# ==========================================
# DELETE SKIN
# ==========================================

@router.delete(
    "/inventory/{skin_id}",
    status_code=204,
)
def delete_skin(
    skin_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    deleted = (
        db.query(Skin)
        .filter(
            Skin.id == skin_id,
            Skin.owner_id == current_user.id,
        )
        .delete(
            synchronize_session=False
        )
    )

    if deleted == 0:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail="Skin not found or no longer owned by user",
        )

    db.commit()

    return None


# ==========================================
# LEADERBOARD
# ==========================================

@router.get(
    "/leaderboard",
    response_model=list[LeaderboardEntry],
)
def leaderboard(
    db: Session = Depends(get_db),
):

    profiles = (
        db.query(Profile)
        .join(User)
        .order_by(
            Profile.level.desc(),
            Profile.kills.desc(),
        )
        .limit(100)
        .all()
    )

    result = []

    for rank, profile in enumerate(
        profiles,
        start=1,
    ):
        result.append(
            LeaderboardEntry(
                rank=rank,
                username=profile.user.username,
                level=profile.level,
                kills=profile.kills,
                deaths=profile.deaths,
                matches=profile.matches,
            )
        )

    return result
