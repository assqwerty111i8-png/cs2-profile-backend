from datetime import datetime

from pydantic import BaseModel, Field


# =========================
# AUTH
# =========================

class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=32,
    )

    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
    )


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# =========================
# PROFILE
# =========================

class ProfileResponse(BaseModel):
    level: int
    kills: int
    deaths: int
    matches: int

    class Config:
        from_attributes = True

class PublicProfileResponse(BaseModel):
    username: str
    level: int
    kills: int
    deaths: int
    matches: int

# =========================
# INVENTORY
# =========================

class SkinCreate(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    weapon: str = Field(
        ...,
        min_length=1,
        max_length=50,
    )

    rarity: str = Field(
        ...,
        min_length=1,
        max_length=30,
    )


class SkinResponse(BaseModel):
    id: int
    name: str
    weapon: str
    rarity: str

    class Config:
        from_attributes = True



# =========================
# LEADERBOARD
# =========================

class LeaderboardEntry(BaseModel):
    rank: int
    username: str
    level: int
    kills: int
    deaths: int
    matches: int
