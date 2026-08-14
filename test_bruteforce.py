import requests

URL = "http://127.0.0.1:8000/login"

data = {
    "username": "alex",      # существующий пользователь
    "password": "wrongpass"  # неправильный пароль
}

for i in range(1, 12):
    response = requests.post(URL, json=data)

    print(
        f"Попытка {i}: "
        f"Status = {response.status_code}, "
        f"Response = {response.text}"
    )