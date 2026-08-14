import requests


URL = "http://127.0.0.1:8000"


token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmVtX3BsYXllciIsInVzZXJfaWQiOjMsImV4cCI6MTc4NjA0MjMxOX0.3KnV33xrHGRmVmgarHWe-RbKbzYP60CuTdEFoOUz1Dw"


headers = {
    "Authorization": f"Bearer {token}"
}


# пытаемся получить чужого пользователя
response = requests.get(
    f"{URL}/users/2",
    headers=headers
)


print(
    "Status:",
    response.status_code
)

print(
    "Response:",
    response.text
)