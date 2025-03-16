import argparse
from scanner import find_open_ports
from scanner import scan_open_ports

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

parse_args()

if port_range != None and (len(port_range) > 2 or (len(port_range) == 2 and int(port_range[0]) > int(port_range[1]))):
    print("Invalid port range")
else:
    find_open_ports(target, port_range)

scan_open_ports()