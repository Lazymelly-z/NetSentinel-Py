from scapy.all import sniff, ARP, IP, TCP, conf,get_if_list, get_working_ifaces
import sys
from detector import netsentinel

guard = None

def get_active_interface():
    interfaces = get_working_ifaces()

    for iface in interfaces:
        if iface.ip != "127.0.0.1" :
            print (f"Auto-selected: {iface.description}({iface.ip})")
            return iface
    return conf.iface 

def main():
    global guard
    guard = netsentinel(trap_ports=[4444, 2222, 8080])
    
    target_iface = get_active_interface()
    print("--- NetSentinel-Py Active ---")
    def process_packet(pkt):
        print(f"[DEBUG] Captured a packet: {pkt.summary()}")
        if guard:
            try:
                guard.check_arp(pkt)
                guard.check_trapport(pkt)
            except Exception as e:
                pass 

    print("[*] Sniffing... Press Ctrl+C to stop.")
    try:
        sniff(iface=target_iface, filter="ip or arp", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()