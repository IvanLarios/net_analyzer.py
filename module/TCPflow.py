from scapy.all import *

class TCPflow:


    def __init__(self, src, dst, srcport, dstport):
        self.ip1 = src
        self.ip2 = dst
        self.port1 = srcport
        self.port2 = dstport
        self.trace = []
    
    def addPacket(self,packet):
        if isinstance(packet, Packet):
            if packet.haslayer(TCP):
                self.trace.append(packet)
    
    def show(self):
        print("TCP flow from: \n")
        print(self.ip1 + ":" + self.port1 + "<-->" + self.ip2+":"+self.port2)

