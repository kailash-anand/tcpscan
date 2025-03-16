from scapy.utils import valid_ip
from scapy.sendrecv import sr, sr1
from scapy.all import TCP, IP

target_IP = None
start_port = -1
end_port = -1
default_ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
open_ports = list()

GET_REQUEST = "GET / HTTP/1.0\r\n\r\n"
GENERIC = "\r\n\r\n\r\n\r\n"

def find_open_ports(address: str, port_range: list) -> None:
    if not valid_ip(address):
        print("Invalid IP")
        return 

    global target_IP
    global start_port
    global end_port
    target_IP = address

    if port_range == None:
        port_range = default_ports
    elif len(port_range) == 1:
        start_port = int(port_range[0])
        end_port = start_port + 1
    else:
        start_port = int(port_range[0])
        end_port = int(port_range[1]) + 1 
    
    for port in range(start_port, end_port):
        if is_port_open(port):
            open_ports.append(port)

    print(open_ports)

def is_port_open(port) -> bool:
    result = sr1(IP(dst=target_IP)/TCP(dport=port, flags="S"), timeout=1, verbose=False)

    if result:
        if result.haslayer(TCP) and result[TCP].flags == 0x12:
            return True

    return False


def scan_open_ports() -> None:
    for port in open_ports:
        synack = sr1(IP(dst=target_IP)/TCP(dport=port, flags="S"), timeout=3, verbose=False)
        if synack and synack.haslayer(TCP) and synack[TCP].flags == 0x12:
            sr1(IP(dst=target_IP)/TCP(dport=port, flags="A"), timeout=3, verbose=False)
  


    return


