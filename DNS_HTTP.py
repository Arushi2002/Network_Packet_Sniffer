from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
import datetime
from datetime import datetime

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
YELLOW = Fore.YELLOW
RESET = Fore.RESET

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    global HTTP_packet_count, DNS_count
    if((HTTP_packet_count>=2) and DNS_count>=3):
                    print("Total number of HTTP packets sniffed=",HTTP_packet_count)
                    print("Total number of DNS packets sniffed=",DNS_count)
                    exit() 
    elif(packet.haslayer(TCP)):
        if(packet.sport==80 or packet.dport==80):
            if packet.haslayer(HTTPRequest):
                # if this packet is an HTTP Request
                #increment number of packets sniffed
                HTTP_packet_count+=1   
                # get the requested URL
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                # get the requester's IP Address
                ip = packet[IP].src
                ip2=packet[IP].dst
                #print(ip2)
                # get the request method
                method = packet[HTTPRequest].Method.decode()
                #Find current time
                now = datetime.now()
                current_time = now.strftime("%H:%M:%S")
                print(f"\n{GREEN}HTTP request at time {current_time}{RESET}")
                byteData=bytes(packet[TCP].payload)
                str1=byteData.decode('UTF-8')
                li=str1.split("\r\n")
                
                for i in li:
                    if i.startswith("Accept-Language:"):
                        j=li.index(i)
                #print(li)
                print(f"Source IP Address: {ip}\nDestination IP Address: {ip2}\nRequested URL: {url}\n{YELLOW}Request method: {method}{RESET}")
                print("Version:1.1")
                if(method=="POST"):
                    for i in li[1:j+1]:
                        print(i)
                else:
                    for i in li[1:]:
                        print(i)
                #if total packets =3 then exit
                
    elif(packet.haslayer(UDP)):
        # In a nutshell, this listens for DNS queries from the victim and shows them to us.
        # This allows us to track the victims activity and perform some useful recon.
        if(packet.sport==53 or packet.dport==53):
            if IP in packet:
                ip_src=packet[IP].src
                ip_dst=packet[IP].dst
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
                    now = datetime.now()
                    print(f"\n{YELLOW}[**] Detected DNS query message at time: {now.time()}{RESET}")
                    #global DNS_count
                    DNS_count+=1
                    byteData=packet.getlayer(DNS).qd.qname
                    str1 = byteData.decode('UTF-8')
                    #print(packet.src)
                    print(f"Source IP address: {str(ip_src)}\nDestination IP address: {str(ip_dst)}\nEthernet Source Address: {packet.src}\nEthernet Destination Address: {packet.dst}\nDNS: ({str1})\n")
                          


#main
DNS_count=0
HTTP_packet_count=0
#sniffing packets
print("Packet sniffer started!!")
sniff(prn=process_packet,store=0,count=0)
print("Total number of DNS packets sniffed=",DNS_count)
print("Total number of HTTP packets sniffed=",HTTP_packet_count)
    