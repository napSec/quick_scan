#!/usr/bin/python3

import nmap
import socket
scanner = nmap.PortScanner()

print("""\n-Quick_Scan NMAP Scanner - 
      
      Automated Internal NMAP All Port -p 1-65535 Scanner 
      
      Featuring nmap scan SYN ACK - UDP and  a comprehensive full scan
      
      Created By: napSec  Information Security Professional - 2022 - \n""")

ip_addr = input("Enter IP to Scan: ")
print("IP being scanned is: ", ip_addr)
type(ip_addr)

resp = input("""\nEnter Scan Type
             1)SYN ACK SCAN
             2)UDP Scan
             3)Comprehensive Scan \n""")
print("You have selected: ", resp)

if resp == '1':
    print("SYN ACK Scan NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("UDP Scan NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("FULL Auto Scan NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-v -sV -sS -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '4':
    print("Quick Scan -p 1-1024 NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sV -sS -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp >= '5':
    print("Wrong option. Try Again")
