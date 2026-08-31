import socket

try:
    result = socket.getaddrinfo(
        "::",
        80,
        type=socket.SOCK_STREAM,
    )

    print("getaddrinfo вернул:")
    for item in result:
        print(item[4][0])

except socket.gaierror as e:
    print("gaierror:", e)