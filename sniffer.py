
from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6, DNS
from datetime import datetime
from pathlib import Path
import csv

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)
CSV_FILE = OUTPUT_DIR / "packets.csv"

packet_count = 0
protocol_counts = {}


def analyze_packet(packet):
    global packet_count

    packet_count += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src_ip = "Unknown"
    dst_ip = "Unknown"
    protocol = "Other"
    src_port = ""
    dst_port = ""
    payload_preview = ""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "DNS" if DNS in packet else "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
    elif IPv6 in packet:
        protocol = "IPv6"

    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    # Show only a short printable preview, never intentionally dump
    # complete packet contents or credentials.
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        raw_payload = bytes(packet.payload.payload)
        if raw_payload:
            payload_preview = "".join(
                chr(byte) if 32 <= byte <= 126 else "."
                for byte in raw_payload[:24]
            )

    print(f"\nPacket #{packet_count}")
    print(f"Time:       {timestamp}")
    print(f"Source IP:  {src_ip}")
    print(f"Dest IP:    {dst_ip}")
    print(f"Protocol:   {protocol}")
    if src_port != "":
        print(f"Source port: {src_port}")
        print(f"Dest port:   {dst_port}")
    print(f"Length:     {len(packet)} bytes")
    if payload_preview:
        print(f"Payload preview: {payload_preview}")

    file_exists = CSV_FILE.exists()
    with CSV_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow([
                "timestamp", "source_ip", "destination_ip",
                "protocol", "source_port", "destination_port",
                "packet_length"
            ])
        writer.writerow([
            timestamp, src_ip, dst_ip, protocol,
            src_port, dst_port, len(packet)
        ])


def main():
    print("=" * 50)
    print("       CODEALPHA BASIC NETWORK SNIFFER")
    print("=" * 50)
    print("Capture only traffic you are authorized to inspect.")
    print("Press Ctrl+C to stop capturing.\n")

    try:
        limit_text = input("Number of packets to capture (0 = unlimited): ")
        packet_limit = int(limit_text)

        if packet_limit < 0:
            print("Please enter zero or a positive number.")
            return

        print("\nStarting capture...")
        sniff(
            prn=analyze_packet,
            count=packet_limit,
            store=False
        )

    except ValueError:
        print("Invalid input. Enter a whole number.")
    except PermissionError:
        print("Permission denied. Check your capture permissions.")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as error:
        print(f"\nCapture error: {error}")
        print("Check Npcap installation and capture permissions.")
    finally:
        print("\nCapture summary")
        print(f"Total packets: {packet_count}")
        for name, count in sorted(protocol_counts.items()):
            print(f"{name}: {count}")
        print(f"CSV output: {CSV_FILE}")


if __name__ == "__main__":
    main()
