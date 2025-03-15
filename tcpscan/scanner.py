from scapy.utils import valid_ip
from scapy.sendrecv import sr
from scapy.all import TCP, IP

target_IP = None
start_port = -1
end_port = -1
default_ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
open_ports = list()

def scan_open_ports(address: str, port_range: list) -> None:
    if not valid_ip(address):
        print("Invalid IP")
        return 

    global target_IP
    target_IP = address 
    
    if port_range == None:
        for x in default_ports:
            if is_port_open(x):
                open_ports.append(x)
    elif len(port_range) == 1:
        start_port = int(port_range[0])
    else:
        start_port = int(port_range[0])
        end_port = int(port_range[1])
        for x in range(start_port, end_port + 1):
            if is_port_open(x):
                open_ports.append(x)

    print(open_ports)

def is_port_open(port) -> bool:
    answered, _ = sr(IP(dst=target_IP)/TCP(dport = port, flags="S"), timeout=1, verbose=False)

    for _, received in answered:
        if received.haslayer(TCP) and received[TCP].flags == 0x12:
            return True

    return False
