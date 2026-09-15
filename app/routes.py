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
    PublicProfileResponse,  # добавить
    SkinCreate,
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
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
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

    existing_user = (
        db.query(User)
        .filter(
            User.username == user.username
        )
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists",
        )

    new_user = User(
        username=user.username,
        hashed_password=hash_password(
            user.password
        ),
    )

    db.add(new_user)
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
        .filter(
            User.username == user.username
        )
        .first()
    )

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    if (
        db_user.locked_until is not None
        and db_user.locked_until
        > datetime.utcnow()
    ):
        raise HTTPException(
            status_code=429,
            detail="Account is temporarily locked",
        )

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

    db_user.failed_attempts = 0
    db_user.locked_until = None

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
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
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
        .filter(
            RevokedToken.jti == jti
        )
        .first()
    )

    if existing_token is not None:
        raise HTTPException(
            status_code=401,
            detail="Token has already been revoked",
        )

    revoked_token = RevokedToken(
        jti=jti,
        expires_at=datetime.fromtimestamp(exp),
    )

    db.add(revoked_token)
    db.commit()

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




# ==========================================
# INVENTORY
# ==========================================

@router.get(
    "/inventory",
    response_model=list[SkinResponse],
)
def get_inventory(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    skins = (
        db.query(Skin)
        .filter(
            Skin.owner_id == current_user.id
        )
        .all()
    )

    return skins


@router.get(
    "/inventory/{skin_id}",
    response_model=SkinResponse,
)
def get_skin(
    skin_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

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
        .filter(Skin.owner_id == user_id)
        .all()
    )



@router.post(
    "/inventory",
    response_model=SkinResponse,
)
@limiter.limit("20/minute")
def add_skin(
    request: Request,
    skin_data: SkinCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    skin_count = (
        db.query(Skin)
        .filter(Skin.owner_id == current_user.id)
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
        owner_id=current_user.id,
    )

    db.add(skin)
    db.commit()
    db.refresh(skin)

    return skin

@router.delete(
    "/inventory/{skin_id}",
    status_code=204,
)
def delete_skin(
    skin_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

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

    db.delete(skin)
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
