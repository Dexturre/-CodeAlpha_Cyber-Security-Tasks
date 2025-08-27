from scapy.all import sniff
import datetime

def packet_callback(packet):
    # Display packet information
    print(f"\n=== Packet Captured at {datetime.datetime.now()} ===")
    print(f"Summary: {packet.summary()}")
    
    # Check if packet has IP layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        protocol_name = get_protocol_name(ip_layer.proto)
        print(f"Protocol: {protocol_name} ({ip_layer.proto})")
        
        # Check for TCP
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"TCP Flags: {tcp_layer.flags}")
            
        # Check for UDP
        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            
        # Check for ICMP
        elif packet.haslayer('ICMP'):
            icmp_layer = packet['ICMP']
            print(f"ICMP Type: {icmp_layer.type}")
            print(f"ICMP Code: {icmp_layer.code}")
        
        # Check for payload
        if packet.haslayer('Raw'):
            raw_layer = packet['Raw']
            payload = raw_layer.load
            print(f"Payload Length: {len(payload)} bytes")
            if len(payload) > 0:
                print(f"Payload (first 50 bytes): {payload[:50]}")
                try:
                    # Try to decode as UTF-8
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                    if decoded_payload.strip():
                        print(f"Decoded Payload: {decoded_payload[:100]}...")
                except:
                    print("Payload contains binary data")
    
    print(f"Total Packet Length: {len(packet)} bytes")
    print("=" * 50)

def start_sniffing(interface=None, count=10, timeout=30):
    # Start sniffing packets
    print("Starting packet capture...")
    print("Press Ctrl+C to stop\n")
    
    try:
        if interface:
            print(f"Listening on interface: {interface}")
            sniff(iface=interface, prn=packet_callback, store=0, count=count, timeout=timeout)
        else:
            print("Using default interface")
            sniff(prn=packet_callback, store=0, count=count, timeout=timeout)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user")
    except Exception as e:
        print(f"Error occurred: {e}")

def get_protocol_name(protocol_num):
    # Map protocol numbers to names
    protocol_map = {
        1: "ICMP",
        6: "TCP", 
        17: "UDP",
        # Add more protocols as needed
    }
    return protocol_map.get(protocol_num, f"Unknown ({protocol_num})")

if __name__ == "__main__":
    # Example usage:
    # start_sniffing(interface="Ethernet", count=20)  # Capture 20 packets on Ethernet interface
    # start_sniffing(count=5, timeout=10)  # Capture 5 packets or timeout after 10 seconds
    start_sniffing(count=10)  # Capture 10 packets
