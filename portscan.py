from urllib.parse import urlparse
import socket
import threading

open_ports = []
lock = threading.Lock()

def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    result = sock.connect_ex((target, port))
    if result == 0:
        with lock:
            print(f"Port {port} is open")
            open_ports.append(port)
    sock.close()

def scan_ports(target, start_port=1, end_port=1024):
    print(f"Scanning {target} from port {start_port} to {end_port} using concurrent TCP connect scan...")
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Unable to resolve hostname '{target}'. Please check the target and try again.")
        return

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not open_ports:
        print("No open ports found in the specified range.")
    else:
        open_ports.sort()
        print(f"Open ports: {open_ports}")

if __name__ == "__main__":
    user_input = input("Enter the target website or IP to scan (can include http:// or https://): ").strip()
    parsed_url = urlparse(user_input)
    if parsed_url.scheme and parsed_url.netloc:
        target = parsed_url.netloc
    else:
        target = user_input
    scan_ports(target)
