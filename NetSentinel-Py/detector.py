from scapy.all import ARP, IP, Ether, srp, conf, TCP
import datetime

class netsentinel:
    def __init__(self, trap_ports=[4444, 8080, 2222]):
        self.known_devices = {} # IP:MAC
        self.trap_ports = trap_ports

    def get_mac(self, ip):
        ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
        if ans : 
            return ans[0][1].hwsrc
        return None
    
    def check_arp(self, pkt) : 
        if pkt.haslayer(ARP) and pkt[ARP].op == 2: 
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

            if src_ip in self.known_devices:
                if self.known_devices[src_ip] != src_mac:
                    print(f" ALERT : Possible ARP poisoning, {src_ip} moved from {self.known_devices[src_ip]} to {src_mac} at {datetime.datetime.now()}")
                else:
                    self.known_devices[src_ip] = src_mac 

    def check_trapport(self, pkt):
        if pkt.haslayer(TCP) and pkt[TCP].dport in self.trap_ports:
            if pkt[TCP].flags == "S": 
                print(f"ALERT : Trapport connection attempt from {pkt[TCP].dport} from {pkt[IP].src} at {datetime.datetime.now()}")