from fastapi import Request

from slowapi import Limiter

from .auth import decode_access_token


def get_user_id_from_jwt(
    request: Request,
) -> str:

    authorization = request.headers.get(
        "Authorization"
    )

    if not authorization:
        return (
            request.client.host
            if request.client
            else "anonymous"
        )

    scheme, _, token = authorization.partition(
        " "
    )

    if (
        scheme.lower() != "bearer"
        or not token
    ):
        return (
            request.client.host
            if request.client
            else "anonymous"
        )

    payload = decode_access_token(token)

    if payload is None:
        return (
            request.client.host
            if request.client
            else "anonymous"
        )

    user_id = payload.get("user_id")

    if user_id is None:
        return (
            request.client.host
            if request.client
            else "anonymous"
        )

    return str(user_id)


limiter = Limiter(
    key_func=get_user_id_from_jwt
)
