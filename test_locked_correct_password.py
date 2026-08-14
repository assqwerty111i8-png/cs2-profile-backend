import requests


URL = "http://127.0.0.1:8000/login"


username = "player123"

wrong_password = "wrongpass"
correct_password = "123456"


# Сначала делаем 10 неправильных входов
print("=== Делаем 10 неправильных попыток ===")

for i in range(1, 11):

    response = requests.post(
        URL,
        json={
            "username": username,
            "password": wrong_password
        }
    )

    print(
        f"Неверный пароль {i}: "
        f"{response.status_code}"
    )


# Теперь пробуем правильный пароль
print("\n=== Проверяем правильный пароль после блокировки ===")


response = requests.post(
    URL,
    json={
        "username": username,
        "password": correct_password
    }
)


print(
    f"Правильный пароль после блокировки: "
    f"Status = {response.status_code}, "
    f"Response = {response.text}"
)