from scapy.all import *
import socket
import datetime
import os
import time
tcp_out_count = 0
icmp_out_count = 0
udp_out_count = 0
tcp_in_count = 0
icmp_in_count = 0
udp_in_count = 0
tcp = 0
icmp = 0
udp = 0
#also tells number of putgoing and incoming packets
def network_monitoring_for_visualization_version(pkt):
    global tcp_out_count ,icmp_out_count ,udp_out_count ,tcp_in_count,icmp_in_count,udp_in_count,tcp,udp,icmp
    tcp_dict = {	'S':"SYN",
                        'A':"ACK",
                        'F':"FIN",
                        'R':"RESET",
                        'P':"PUSH",
                        'U':"URGENT"}
    time=datetime.datetime.now()
    if pkt.haslayer(TCP):
        tcp+=1
        print("TCP PACKET READ")
        print()
        print("Ether src  :",pkt.src)
        print("Ether dst  :",pkt.dst)
        print("Src port no  :",pkt.sport)
        print("Dst port no  :",pkt.dport)
        print("FLAGS")
        print()
        for i in pkt[TCP].flags:
            print(tcp_dict[i])
        print()
        #pkt.show()
        try:
            k = pkt[IP].src
            print("IP PACKET(TCP)")
            print("IP src  :",pkt[IP].src)
            if(pkt[IP].src == '192.168.29.177'):
                tcp_out_count+=1;
            if(pkt[IP].dst == '192.168.29.177'):
                tcp_in_count+=1;
            print("IP dst  :",pkt[IP].dst)
            
        except:
            pass


        
    if pkt.haslayer(UDP):
        udp+=1
        print("UDP PACKET READ")
        print()
        print("Ether src  :",pkt.src)
        print("Ether dst  :",pkt.dst)
        print("Src port no  :",pkt.sport)
        print("Dst port no  :",pkt.dport)
        print("Packet length  :",pkt[UDP].len)
        #pkt.show()
        try:
            k = pkt[IP].src
            print("IP PACKET(UDP)")
            if(pkt[IP].src == '192.168.29.177'):
                udp_out_count+=1;
            if(pkt[IP].dst == '192.168.29.177'):
                udp_in_count+=1;
            print("IP src  :",pkt[IP].src)
            print("IP dst  :",pkt[IP].dst)
            
        except:
            pass


    if pkt.haslayer(ICMP):
        icmp+=1
        print("ICMP PACKET READ")
        print()
        print("Ether src  :",pkt.src)
        print("Ether dst  :",pkt.dst)
        print("Src port no  :",pkt.sport)
        print("Dst port no  :",pkt.dport)
        try:
            k = pkt[IP].src
            print("IP PACKET(ICMP)")
            if(pkt[IP].src == '192.168.29.177'):
                icmp_out_count+=1;
            if(pkt[IP].dst == '192.168.29.177'):
                icmp_in_count+=1;
            print("IP src  :",pkt[IP].src)
            print("IP dst  :",pkt[IP].dst)
            
        except:
            pass


    
if __name__ == '__main__':
    print("STARTING PACKET SNIFFING")
    #function executed with every packet sniffed
    sniff(prn=network_monitoring_for_visualization_version,count = 50)
    print("TCP INCOMING")
    print(tcp_in_count)
    print("TCP OUTGOING")
    print(tcp_out_count)
    print("UDP INCOMING")
    print(udp_in_count)
    print("UDP OUTGOING")
    print(udp_out_count)
    print("ICMP INCOMING")
    print(icmp_in_count)
    print("ICMP OUTGOING")
    print(icmp_out_count)
    print("TOTAL TCP PACKETS")
    print(tcp)
    print("TOTAL UDP PACKETS")
    print(udp)
    print("TOTAL ICMP PACKETS")
    print(icmp)
