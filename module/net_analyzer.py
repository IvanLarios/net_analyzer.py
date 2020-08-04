# encoding: utf-8

import socket
from scapy.all import *
from scapy.layers import dns
from scapy.layers.inet import IP, TCP, UDP
import TCPflow

IRC_commands = ['ADMIN', 'AWAY', 'CNOTICE', 'CPRIVMSG', 'CONNECT', 'DIE', 'ENCAP', 'ERROR', 'HELP', 'INFO',\
                'INVITE', 'ISON', 'JOIN', 'KICK', 'KILL', 'NOCK', 'LINKS', 'LIST', 'LUSERS', 'MODE', 'MOTD',\
                'NAMES', 'NAMESX', 'NICK', 'NOTICE', 'OPER', 'PART', 'PASS', 'PING', 'PONG', 'PRIVMSG', 'QUIT',\
                'REHASH', 'RESTART', 'RULES', 'SERVER', 'SERVICE', 'SERVLIST', 'SQUERY', 'SQUIT', 'SETNAME',\
                'SILENCE', 'STATS', 'SUMMON', 'TIME', 'TOPIC', 'TRACE', 'UHNAMES', 'USER', 'USERHOST', 'USERIP',\
                'USERS', 'VERSION', 'WALLOPS', 'WATCH', 'WHO', 'WHOIS', 'WHOWAS']

def analyze_DNS(packet):
    auxdict = {}

    #################################
    ### Domain Queries extraction ###
    #################################
    
    # No comprobamos la capa DNSQR ya que el protocolo MDNS puede dar problemas ya que algunos paquetes no
    # contienen la query a la que responden.
    if packet.haslayer(DNSRR):
        key = packet[DNSRR].rrname.decode("utf-8")
        auxdict[key] = []
        for i in range(packet[DNS].ancount):       
            auxdict[key].append(packet[DNSRR][i].rdata)
    return auxdict

def analyze_IP(packet, abnormal_list):
    
    ####################################
    ### TTL Analysis ###################
    ####################################

    abFlag = 0
    ttl = packet.ttl
    # TTL analyzer -> Basado en "Using abnormal TTL values to detect malicious IP packets" de Yamada, R. y Goto, S.
    if (1 < ttl <= 30) or (64 < ttl <= 98) or (128< ttl <= 225):
        abnormal_list.append(packet)
        abFlag = 1

    ####################################
    ### IP extraction ##################
    ####################################

    ip_dict = {}
    ip_dict[packet[IP].src] = abFlag
    ip_dict[packet[IP].dst] = abFlag

    return ip_dict

def traffic_parser(sample_name, hostIP, sshPort):
    clean_trace = []
    packets = rdpcap(sample_name+".pcap")
    #Eliminamos paquetes de nuestra conexión con la sandbox
    for packet in packets:
        if packet.haslayer(TCP):
            if not(packet[TCP].sport is sshPort and packet[IP].src is hostIP) or (packet[TCP].dport is sshPort and packet[IP].dst is hostIP):
                clean_trace.append(packet)
        else:
            clean_trace.append(packet)

    return clean_trace

def trace_analyzer(trace):
    IP_list = {}
    protocol_list = []
    TTL_suspicious_packets = []
    prototemp_list =  []
    DNS_dict = {}
    for packet in trace:
        if packet.haslayer(IP):
            prototemp_list.append(packet.proto)
            result = analyze_IP(packet, TTL_suspicious_packets)
            # If the IPs obtained are not in the dictionary we add them
            if result.keys() not in IP_list.keys():
                IP_list.update(result)
            # If the IPs are in the dictionary already we check if they were marked as suspicious
            else:
                for key in result.keys():
                    if IP_list[key] != result[key]:
                        # If they were once marked as suspicious IPs, they remain suspicious
                        IP_list[key] = 1

        if packet.haslayer(DNS):
            protocol_list.append("DNS")
            DNS_dict.update(analyze_DNS(packet))
        # if packet.haslayer(IRC):
        #    prototemp_list.append(packet.proto)

  

    #Socket class has stored every protocol prefixed with "IPPROTO" with it's number given by the IANA
    table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    for proto in set(prototemp_list):
        protocol_list.append(table[proto])
    
    fIP = open ("C:\\PRUEBASDESO\\IP.txt", "w")
    fDNS = open("C:\\PRUEBASDESO\\DNS.txt", "w")
    fprt = open("C:\\PRUEBASDESO\\Proto.txt", "w")

    fIP.write(str(IP_list))
    fDNS.write(str(DNS_dict))
    fprt.write(str(protocol_list))





def main(file):
    trace = traffic_parser(file,"10.0.0.100", 22)
    trace_analyzer(trace)

main("C:\\PRUEBASDESO\\TRAFFICEX")
