from audioop import add
from concurrent.futures import thread
import os
import platform
import argparse
from re import L
import socket
import threading
from queue import Queue
import time


print_lock = threading.Lock()
q = Queue()

def threader_tcp_scan():
    while True:
        port = q.get()
        tcp_scan(port)
        q.task_done()

def threader_icmp_scan():
    while True:
        ip = q.get()
        icmp_scan(ip)
        q.task_done()

def os_info():
    os_sys = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    os_machine = platform.machine()
    os_platform = platform.platform()
    print("="*10,"OS Infomation", "="*10 ,"\nSystem: %s \nRelease: %s \nVersion: %s \nMachine: %s \nPlatform: %s" %(os_sys,os_release,os_version,os_machine,os_platform))

def icmp_scan(ip):
    oper = platform.system()
    if (oper == "Windows"):
       ping1 = "ping -n 1 "
    elif (oper == "Linux"):
        ping1 = "ping -c 1 "
    else :
        ping1 = "ping -c 1 "

    comm = ping1 + ip
    response = os.popen(comm)
    for line in response.readlines():
        line = line.lower()
        if(line.count("ttl")):
            print(ip, "--> Live")
    
            

def tcp_scan(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        
        result = sock.connect_ex((args.ip,port))
        if result == 0:
            print("Port %d: OPEN" %(port))
            sock.close()
            
    except socket.error:
        print("Could not connect to IP")
        




def main(args):
        if args.mode.lower() == "p":
            print ("Scanning in Progress:")
            startTime = time.time()
            if args.ip:
                icmp_scan(args.ip)
                
                
            if args.network:
                net = args.network
                net1= net.split('.')
                a = '.'

                net2 = net1[0] + a + net1[1] + a + net1[2] + a
            
                if args.start:
                    start1 = args.start
                else:
                    start1 = 1
                
                if args.last:
                    last1 = args.last
                    last1 += 1
                else:
                    last1 = 255
                
                if args.fast:
                    for x in range(start1, last1):
                        t = threading.Thread(target = threader_icmp_scan)
                        t.daemon = True
                        t.start()
                        
                    for ip in range(start1,last1):
                        addr = net2 + str(ip)
                        q.put(addr)
                        
                    q.join()
                    
                else:    
                    for ip in range(start1,last1):
                        addr = net2 + str(ip)
                        icmp_scan(addr)
            print ("Scanning complete")
            print('Time taken:', time.time() - startTime)
            
        elif args.mode.lower() == "os":
            os_info()
            
        elif args.mode.lower() == "ps":
            if args.ip:
                if args.start:
                    start2 = args.start
                else:
                    start2 = 0
                    
                if args.last:
                    last2 = args.last
                else:
                    last2 = 65535
                    
                print ("Scanning in Progress:")
                startTime = time.time()
                if args.fast:
                    
                    for x in range(start2,last2):
                        t = threading.Thread(target = threader_tcp_scan)
                        t.daemon = True
                        t.start()
                        
                    for worker in range(start2,last2):
                        q.put(worker)
                        
                    q.join()
                    
                else:
                    
                    for port in range(start2,last2):
                        tcp_scan(port)
                print ("Scanning complete")
                print('Time taken:', time.time() - startTime)
                
                
            else:
                print("not supported") 
        else:
            print("Please only use '-m p' or '-m os' or '-m ps' only")
        




if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     usage="network_scan.py [-h] [-m p -ip 192.168.1.1] [-m p -n 192.168.1.1] [-m p -n 192.168.1.1 -s 1 -l 100] [-m os] [-m ps -ip 192.168.1.1] [-m ps -ip 192.168.1.1 -l 1024]",
                                     description="Scan the network to find out which ip are alive or which port is avaible as well as giving some basic os information")
    parser.add_argument("-m", "--mode", choices=["p", "os", "ps"] ,help="select the mode to run e.g 'p' will do a ping scan, 'os' will give os information, 'ps' will do a port scan")
    parser.add_argument("-ip", help="Specify the ip")
    parser.add_argument("-s", "--start", type=int, help="Specify the starting number for network address or port number")
    parser.add_argument("-l", "--last", type=int, help="Specify the last number for network address or port number")
    parser.add_argument("-f", "--fast", action="store_true", help="Fast mode which uses thread to speed up the scan")
    ping = parser.add_argument_group("PING", "'-m p' Send an ICMP to the specified host/network to determine whether the host is alive or dead")
    ping.add_argument("-n", "--network", help="Specify the network address (If -s and -l is not specify it will scan the whole network which is /24 or 255)")
    osinfo = parser.add_argument_group("OS INFORMATION", "'-m OS' Shows basic OS information")
    port_scan = parser.add_argument_group("PORT SCAN", ''''-m ps' Send a TCP packet to the specifed IP to figure out which port is/are open 
                                            \n\tIf -s is not specify it will start from port 0 else it will start from -s
                                            \n\tIf -l is not specify it will end at 65535 else it will ends from -l''')
    
    args = parser.parse_args()
    main(args)

            
