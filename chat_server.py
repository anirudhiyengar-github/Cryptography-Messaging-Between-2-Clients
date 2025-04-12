import socket
import threading

clients = []

def handle_client(conn, addr):
    print(f"Connected: {addr}")
    clients.append(conn)

    partner = [c for c in clients if c != conn][0]
    conn.send(partner.recv(2048))
    partner.send(conn.recv(2048))

    while True:
        try:
            msg = conn.recv(4096)
            if msg:
                partner.send(msg)
        except:
            conn.close()
            break

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(2)
    print("Server started on port 12345")
    
    while len(clients) < 2:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

start_server()
