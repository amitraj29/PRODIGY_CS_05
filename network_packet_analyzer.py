import scapy.all as scapy

def packet_sniffer(interface):
    print(f"[*] Starting packet sniffer on interface {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None

        print(f"[+] New Packet: {ip_src} --> {ip_dst} Protocol: {protocol} Payload: {payload}")

def main():
    interface = input("Enter the interface to sniff packets (e.g., eth0, wlan0): ")
    packet_sniffer(interface)

if __name__ == "__main__":
    main()