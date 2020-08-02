# encoding: utf-8

import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def traffic_parser(sample_name, hostIP, sshPort):
    clean_trace = []
    packets = rdpcap(sample_name+".pcap")
    #Eliminamos paquetes de nuestra conexión con la sandbox
    for packet in packets:
        if packet.haslayer(TCP):
            if not(packet[TCP].sport is sshPort and packet[IP].src is hostIP) or (packet[TCP].dport is sshPort and packet[IP].dst is hostIP):
                clean_trace.append(packet)

    return clean_trace

def trace_analyzer(trace):
    IP_list = []
    protocol_list = []
    IPtemp_list = []
    prototemp_list =  []
    for packet in trace:
        if packet.haslayer(IP):
            IPtemp_list.append(packet[IP].src)
            IPtemp_list.append(packet[IP].dst)
            prototemp_list.append(packet.proto)

  


    table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    for proto in prototemp_list:
        protocol_list.append(table[proto])
    IP_list = set(IPtemp_list)
    protocol_list = set(protocol_list)
    
    fIP = open ("C:\\PRUEBASDESO\\IP.txt", "w")
    fprt = open("C:\\PRUEBASDESO\\Proto.txt", "w")
    fIP.write(str(IP_list))
    fprt.write(str(protocol_list))

def main(file):
    trace = traffic_parser(file,"10.0.0.100", 22)
    trace_analyzer(trace)

main("C:\\PRUEBASDESO\\TRAFFICEX")
