import socket
import requests
import nmap
from datetime import datetime

with open('/root/Documents/networkscanner1/assets/logo.txt', 'r') as f:
    print(f.read())
print('=' * 60)
print()








def port_scan(target, start_port, end_port):
         print(f"scanning target: {target} for open ports from {start_port} to {end_port}...")
         open_ports = []
         for port in range(start_port, end_port):
                  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  socket.setdefaulttimeout(1)
                  result = sock.connect_ex((target, port))
                  if result == 0:
                          open_ports.append(port)
                  sock.close()
         return open_ports




def banner_grab(target, port):
        print(f"Grabbing banner for {target}:{port}")
        try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((target, port))
                sock.settimeout(2)
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner.strip()
        except:
                return None



def vulnerbility_scan(target):
        print(f"scanning target {target} for vulnerabilties...")
        nm = nmap.PortScanner()
        try:
                nm.scan(hosts=target, arguments="-O -sV --script=vuln")
                return nm[target]
        except Exception as e:
                print(f"Error during vulnerability scan: {e}")
                return None



def network_scan(target, start_port, end_port):
        print(f"starting network scan for target: {target}..")
        start_time = datetime.now()


        open_ports = port_scan(target, start_port, end_port)
        if open_ports:
                print(f"open ports found: {open_ports}")
        else:
                print("No open ports found")
        for port in open_ports:
                banner = banner_grab(target, port)
                if banner:
                        print(f"Banner for {target}:{port} - {banner}")
                else:
                        print(f"No banner found for {target}:{port}")
        vuln_info = vulnerbility_scan(target)
        if vuln_info:
                if 'hostname' in vuln_info:
                        print(f"Hostnames: {vuln_info['hostnames']}")
                if 'osmatch' in vuln_info:
                        print(f"Operating System: {vuln_info['osmatch']}")
                if 'vulns' in vuln_info:
                        print(f"Vulnerabilities: {vuln_info['vulns']}")
        else:
                print("No vulnerabilties detected or unableto detect.")
        end_time = datetime.now()
        print(f"scan completed in: {end_time - start_time}")




if __name__ == "__main__":
        target_ip = input("Enter the target IP or Hostname: ")
        start_port = int(input("Enter the starting port for scanning: "))
        end_port = int(input("Enter the ending port for scanning: "))
        network_scan(target_ip, start_port, end_port)
