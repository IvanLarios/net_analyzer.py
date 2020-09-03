# encoding: utf-8

import json
import socket
import time

import requests
from netaddr import *
from scapy.all import *
from scapy.layers import dns
from scapy.layers.inet import IP, TCP, UDP

from config import *

# VT Key only valid   for 4 req/min
vt_key = getKey()

#  IRC_commands = ['ADMIN', 'AWAY', 'CNOTICE', 'CPRIVMSG', 'CONNECT', 'DIE', 'ENCAP', 'ERROR', 'HELP', 'INFO',\
#                 'INVITE', 'ISON', 'JOIN', 'KICK', 'KILL', 'NOCK', 'LINKS', 'LIST', 'LUSERS', 'MODE', 'MOTD',\
#                 'NAMES', 'NAMESX', 'NICK', 'NOTICE', 'OPER', 'PART', 'PASS', 'PING', 'PONG', 'PRIVMSG', 'QUIT',\
#                 'REHASH', 'RESTART', 'RULES', 'SERVER', 'SERVICE', 'SERVLIST', 'SQUERY', 'SQUIT', 'SETNAME',\
#                 'SILENCE', 'STATS', 'SUMMON', 'TIME', 'TOPIC', 'TRACE', 'UHNAMES', 'USER', 'USERHOST', 'USERIP',\
#                 'USERS', 'VERSION', 'WALLOPS', 'WATCH', 'WHO', 'WHOIS', 'WHOWAS']

#################################################
### Se realiza una vez para que no se sobrepasen el limite
### de 4 request/min
#################################################

def vt_request(IPs):
    results = {}
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    for ip in IPs:
        params = {'apikey': vt_key, 'ip': ip}
        time.sleep(15.1)
        response = requests.get(url, params=params)
        data = response.json()
        if data['response_code'] == 1:
            results[ip] = data
        else:
            results[ip] = 0
    return results



def analyze_TCP(packet, connectDict):

    if packet.haslayer(TCP):
        if str(packet[TCP].flags) == "S":
            if packet[IP].src in connectDict:
                if packet[IP].dst in connectDict[packet[IP].src]:
                    connectDict[packet[IP].src][packet[IP].dst]['counter'] += 1
                else:
                    connectDict[packet[IP].src][packet[IP].dst] = \
                    {'sport' : packet[TCP].sport, 'dport' : packet[TCP].dport, 'counter' : 1}
            else:
                connectDict[packet[IP].src] = {}
                connectDict[packet[IP].src][packet[IP].dst] = \
                    {'sport' : packet[TCP].sport, 'dport' : packet[TCP].dport, 'counter' : 1}


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
        #abnormal_list.append(packet)
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
    port_list = []
    TTL_suspicious_packets = []
    prototemp_list =  []
    DNS_dict = {}
    IP2req = []
    conDict = {}

    for packet in trace:
        if packet.haslayer(IP):
            prototemp_list.append(packet.proto)
            result = analyze_IP(packet, TTL_suspicious_packets)
            # If the IPs obtained are not in the dictionary we add them
            if not all(key in result.keys() for key in IP_list.keys()):
                IP_list.update(result)
            # If the IPs are in the dictionary already we check if they were marked as suspicious
            else:
                for key in result.keys():
                    if not key in IP_list:
                        IP_list[key] = result[key]
                    elif IP_list[key] != result[key]:
                        # If they were once marked as suspicious IPs, they remain suspicious
                        IP_list[key] = 1
        if packet.haslayer(TCP):
            if packet[TCP].sport < 49151:
                port_list.append(packet[TCP].sport)
            if packet[TCP].dport < 49151:
                port_list.append(packet[TCP].dport)
            analyze_TCP(packet, conDict)
        if packet.haslayer(DNS):
            protocol_list.append("DNS")
            DNS_dict.update(analyze_DNS(packet))
        # if packet.haslayer(IRC):
        #    prototemp_list.append(packet.proto)

    ####################################
    #### RESULT PREPARATION ############
    ####################################
  
    #Socket class has stored every protocol prefixed with "IPPROTO" with it's number given by the IANA. Credits: https://stackoverflow.com/questions/37004965/how-to-turn-protocol-number-to-name-with-python
    table = {num: name[8:] for name, num in vars(
        socket).items() if name.startswith("IPPROTO")}
    for proto in set(prototemp_list):
        protocol_list.append(table[proto])
    port_list = list(set(port_list))
    list.sort(port_list)

    for ip in IP_list.keys():
        if not (IPAddress(ip).is_private() or IPAddress(ip).is_loopback()):
            if IP_list[ip] == 1:
                IP2req.append(ip)

    for key in conDict:
        for key2 in conDict[key]:
            if conDict[key][key2]['counter'] > 5:
                if not (IPAddress(key2).is_private() or IPAddress(key2).is_loopback()):
                    IP2req.append(key2)
                if not (IPAddress(key).is_private() or IPAddress(key).is_loopback()):
                    IP2req.append(key)

    # We send the suspicious IPs to get their reports from VirusTotal
    results = vt_request(IP2req)

    fIPvt = open ("C:\\PRUEBASDESO\\vtIPresults.json", "w")
    fDNS = open("C:\\PRUEBASDESO\\DNS.txt", "w")
    fprt = open("C:\\PRUEBASDESO\\Ports.txt", "w")
    fDict = open("C:\\PRUEBASDESO\\ConDict.json", "w")

    fIPvt.write(json.dumps(results, indent=2))
    fDNS.write(str(DNS_dict))
    fprt.write("Protocol list\n" + str(set(protocol_list)))
    fprt.write("\nPort list\n" + str(port_list))
    fDict.write(json.dumps(conDict, indent=2))




def main(file):
    trace = traffic_parser(file,"10.0.0.100", 22)
    trace_analyzer(trace)

main("C:\\PRUEBASDESO\\TRAFFICEX")
