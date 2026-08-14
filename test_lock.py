import requests


URL = "http://127.0.0.1:8000/login"


data = {
    "username": "player123",   # существующий пользователь
    "password": "wrongpass"    # неправильный пароль
}


for attempt in range(1, 12):

    response = requests.post(
        URL,
        json=data
    )

    print(
        f"Попытка {attempt}: "
        f"Status = {response.status_code}, "
        f"Response = {response.text}"
    )