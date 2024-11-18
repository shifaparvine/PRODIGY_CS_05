from scapy.all import sniff, IP, TCP, UDP
import argparse

def analyze_packet(packet):
  
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

       
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = packet[TCP].payload

            print(f"[TCP] {ip_src}:{src_port} -> {ip_dst}:{dst_port} | Payload: {payload}")

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = packet[UDP].payload

            print(f"[UDP] {ip_src}:{src_port} -> {ip_dst}:{dst_port} | Payload: {payload}")

        else:
            print(f"[IP] {ip_src} -> {ip_dst} | Protocol: {protocol}")


def start_sniffer(interface):
    print(f"Starting packet sniffer on interface: {interface}")
    sniff(iface=interface, prn=analyze_packet, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer Tool")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to sniff on")
    args = parser.parse_args()

    try:
        start_sniffer(args.interface)
    except PermissionError:
        print("Permission denied: Please run as root/admin.")
    except KeyboardInterrupt:
        print("\nExiting packet sniffer.")

