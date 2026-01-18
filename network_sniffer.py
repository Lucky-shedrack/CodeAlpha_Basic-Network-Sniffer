from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet):
    print("\n=== PACKET CAPTURED ===")

    if IP in packet:
        ip = packet[IP]
        print(f"Source IP:      {ip.src}")
        print(f"Destination IP: {ip.dst}")

        # Protocol detection
        if ip.proto == 6:
            print("Protocol:       TCP")
        elif ip.proto == 17:
            print("Protocol:       UDP")
        elif ip.proto == 1:
            print("Protocol:       ICMP")
        else:
            print(f"Protocol:       {ip.proto}")

        # TCP details
        if TCP in packet:
            tcp = packet[TCP]
            print(f"TCP | SrcPort: {tcp.sport}  →  DstPort: {tcp.dport}")

        # UDP details
        if UDP in packet:
            udp = packet[UDP]
            print(f"UDP | SrcPort: {udp.sport}")

        # Raw Payload
        if Raw in packet:
            data = packet[Raw].load
            try:
                print(f"Payload: {data[:60]}")
            except:
                print("Payload: [Binary]")

def start_sniffer():
    print("Sniffer running... Press CTRL+C to stop.")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffer()


