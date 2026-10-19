import sys
from SocketTCP import SocketTCP

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cliente.py <ip> <puerto> < archivo", file=sys.stderr)
        sys.exit(1)

    address = (sys.argv[1], int(sys.argv[2]))
    file_msg = sys.stdin.buffer.read()

    # CLIENT
    client_socketTCP = SocketTCP()
    client_socketTCP.connect(address)
    client_socketTCP.send(file_msg)
    client_socketTCP.close()

    print(f"Cliente: {len(file_msg)} bytes enviados.\n", file=sys.stderr)


if __name__ == "__main__":
    main()