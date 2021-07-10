import socket
import sys
import os
import logging
import struct

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
)

serverAddr = '/var/run/smith_agent.sock'

def serverSocket():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    if os.path.exists(serverAddr):
        os.unlink(serverAddr)

    sock.bind(serverAddr)
    sock.listen(5)

    logging.info("server start")

    while True:
        conn, clientAddr = sock.accept()

        try:
            while True:
                header = conn.recv(4)
                if header:
                    payload_size = struct.Struct(">i").unpack(header)[0]
                    payload = conn.recv(payload_size)

                    logging.info("payload %s", payload.decode('utf8'))
                else:
                    break
        finally:
            conn.close()

    os.unlink(serverAddr)

if __name__ == "__main__":
    serverSocket()
