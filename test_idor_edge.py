import requests


URL = "http://127.0.0.1:8000"

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmVtX3BsYXllciIsInVzZXJfaWQiOjMsImV4cCI6MTc4NjA0MjMxOX0.3KnV33xrHGRmVmgarHWe-RbKbzYP60CuTdEFoOUz1Dw"


headers = {
    "Authorization": f"Bearer {TOKEN}"
}


for user_id in [-1, 0]:

    response = requests.get(
        f"{URL}/users/{user_id}",
        headers=headers
    )

    print(
        f"user_id={user_id}: "
        f"Status={response.status_code}, "
        f"Response={response.text}"
    )