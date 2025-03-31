import argparse
from .scanner import find_open_ports
from .scanner import scan_open_ports

port_range = None
target = None

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--port_range")
    parser.add_argument("target")

    args = parser.parse_args()

    global port_range
    global target

    port_range = args.port_range
    target = args.target

    if port_range != None:
        port_range = port_range.split("-")

def main():
    global port_range
    global target
    parse_args()

    if port_range != None and (len(port_range) > 2 or (len(port_range) == 2 and int(port_range[0]) > int(port_range[1]))):
        print("Invalid port range")
    else:
        if port_range and len(port_range) != 1:
            start_port = int(port_range[0])
            end_port = int(port_range[1]) + 1
            port_range = []

            for port in range(start_port, end_port):
                port_range.append(port)
        elif port_range:
            port = int(port_range[0])
            port_range = []
            port_range.append(port)

        find_open_ports(target, port_range)
        scan_open_ports()

if __name__ == "__main__":
    main()
