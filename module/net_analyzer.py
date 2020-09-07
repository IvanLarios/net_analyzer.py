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
import argparse

# VT Key only valid   for 4 req/min
vt_key = getKey()

parser = argparse.ArgumentParser(
    description='Obtains useful information about suspicious packets in the given trace.')

parser.add_argument(
    "-p", "--path", default="C:\\PRUEBASDESO\\TRAFFICEX", help="Pcap file path.")
parser.add_argument(
    "-a", "--address", help="Address of the host connected to the sandbox.")

args = parser.parse_args()

path = str(args.path)
addr = str(args.address)
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
        key = str(packet[DNSRR].rrname.decode("utf-8"))
        auxdict[key] = []
        for i in range(packet[DNS].ancount):       
            auxdict[key].append(str(packet[DNSRR][i].rdata))
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
    if hostIP != None:
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
            if (packet[TCP].sport > 1024) and (packet[TCP].dport > 1024):
                port_list.append(min(packet[TCP].sport, packet[TCP].dport))
            elif packet[TCP].dport < 1024:
                port_list.append(packet[TCP].dport)
            elif packet[TCP].sport < 1024:
                port_list.append(packet[TCP].sport)
            analyze_TCP(packet, conDict)
        if packet.haslayer(DNS):
            protocol_list.append("DNS")
            DNS_dict.update(analyze_DNS(packet))

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

    fIPvt = open("..\\results\\vtIPresults.json", "w")
    fDNS = open("..\\results\\DNS.json", "w")
    fprt = open("..\\results\\Ports.txt", "w")
    fDict = open("..\\results\\ConDict.json", "w")

    fIPvt.write(json.dumps(results, indent=2))
    fDNS.write(json.dumps(DNS_dict, indent=4))
    fprt.write("Protocol list\n" + str(set(protocol_list)))
    fprt.write("\nPort list\n" + str(port_list))
    fDict.write(json.dumps(conDict, indent=2))


def net_analyzer(file):
    trace = traffic_parser(file,addr, 22) #Change port if SSH is ran in a different port.
    trace_analyzer(trace)
#Comment the following line if you integrate this module
net_analyzer(path)
