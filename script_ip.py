import socket

HOST = '10.0.2.5'
PORT = 65432
 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = s.recv(1024)
    with open('network_activity.txt', 'wb') as f:
        f.write(data)
    print("Fișierul a fost primit cu succes")
