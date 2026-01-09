import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 5000))
s.listen(1)
print("SOC Server listening on port 5000...")
while True:
    conn, addr = s.accept()
    data = conn.recv(1024).decode()
    print(f"ALERT RECEIVED: {data}")
    conn.close()
