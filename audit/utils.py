import socket

def scan_port(ip, port, timeout=0.3):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0
    except:
        return False
