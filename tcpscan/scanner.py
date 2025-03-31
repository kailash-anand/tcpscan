import ssl
import socket
import select
import ipaddress

target_IP = None
default_ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
open_ports = list()
scanned = False

GET_REQUEST = "GET / HTTP/1.0\r\n\r\n"
GENERIC = "\r\n\r\n\r\n\r\n"

STATE_TABLE = {
    1: "TCP server-initiated",
    2: "TLS server-initiated",
    3: "HTTP server",
    4: "HTTPS server",
    5: "Generic TCP server",
    6: "Generic TLS server"
}

def find_open_ports(address: str, port_range: list) -> None:
    global target_IP

    if not is_ip(address):
        target_IP = resolve_domain(target_host)
    else:
        target_IP = address

    if port_range == None:
        port_range = default_ports

    print("Scanning for open ports...")

    for port in port_range:
        if is_port_open(port):
            open_ports.append(port)

    print("Open ports identified: " + str(open_ports))

def is_port_open(port) -> bool:
    try:
        sock = socket.create_connection((target_IP, port), timeout=1)
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception as e:
        print(str(e)) 
        print("Aborting scan...")
        return

def scan_open_ports() -> None:
    print("Connecting to open ports...")
    global scanned

    for port in open_ports:
        if not scanned:
            server_scan_open_tcp_port(port)

        if not scanned:
            server_scan_open_tls_port(port)

        if not scanned:
            client_scan_open_tls_port(port)

        if not scanned:
            client_scan_open_tcp_port(port)

        if not scanned:
            client_scan_open_generic_tls_port(port)

        if not scanned:
            client_scan_open_generic_tcp_port(port)

        scanned = False

def server_scan_open_tcp_port(port):
    global scanned
    data = None
    try:
        sock = socket.create_connection((target_IP, port), timeout=3)
    
        readable, _, _ = select.select([sock], [], [], 1)
        if readable:
            data = sock.recv(1024, socket.MSG_DONTWAIT).decode('utf-8', errors='replace')
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

            if data:
                scanned = True
                print_info(1, port, data)
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def server_scan_open_tls_port(port):
    global scanned
    data = None
    try:
        sock = socket.create_connection((target_IP, port), timeout=3)

        context = ssl.create_default_context()
        ssock = context.wrap_socket(sock)

        sreadable, _, _ = select.select([ssock], [], [], 1)
        if sreadable:
            data = ssock.recv(1024).decode('utf-8', errors='replace')
            ssock.shutdown(socket.SHUT_RDWR)
            ssock.close()
            
            if data:
                scanned = True
                print_info(2, port, data)
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def client_scan_open_tcp_port(port):
    global scanned
    data = None
    try:
        sock = socket.create_connection((target_IP, port), timeout=3)

        sock.send(GET_REQUEST.encode('utf-8'))
        readable, _, _ = select.select([sock], [], [], 1)

        if readable:
            data = sock.recv(1024).decode('utf-8', errors='replace')
            sock.close()

            if data:
                scanned = True
                print_info(3, port, data)  
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def client_scan_open_tls_port(port):
    global scanned
    data = None
    ssock = None
    try:
        sock = socket.create_connection((target_IP, port), timeout=3)
        context = ssl.create_default_context()
        ssock = context.wrap_socket(sock)
    
        ssock.send(GET_REQUEST.encode('utf-8'))
        sreadable, _, _ = select.select([ssock], [], [], 1)

        if sreadable:
            data = ssock.recv(1024).decode('utf-8', errors='replace')
            ssock.close()
            if data:
                scanned = True
                print_info(4, port, data)
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def client_scan_open_generic_tcp_port(port):
    global scanned
    data = None
    try:
        sock = socket.create_connection((target_IP, port), timeout=3)
        sock.send(GENERIC.encode('utf-8'))
        readable, _, _ = select.select([sock], [], [], 1)

        if readable:
            data = sock.recv(1024).decode('utf-8', errors='replace')
            
        scanned = True
        print_info(5, port, data)
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def client_scan_open_generic_tls_port(port):
    global scanned
    data = None
    ssock = None
    try:
        sock = socket.create_connection((target_IP, port), timeout=3)
        context = ssl.create_default_context()
        ssock = context.wrap_socket(sock)
        ssock.send(GENERIC.encode('utf-8'))

        sreadable, _, _ = select.select([ssock], [], [], 1)
        if sreadable:
            data = ssock.recv(1024).decode('utf-8', errors='replace')
            
        ssock.close() 
        scanned = True
        print_info(6, port, data)
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def is_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        print(f"Failed to resolve {domain}: {e}")
        return None

def sanitize_output(data: str) -> str:
    return ''.join(c if 32 <= ord(c) < 127 else '.' for c in data)   

def print_info(type: int, port: int, data: str) -> None:
    print("------------------------------------")
    print("Host:", str(target_IP) + ":" + str(port))
    print("Type: (", type, ")", STATE_TABLE.get(type))
    print("Response:", sanitize_output(data[:1024]))