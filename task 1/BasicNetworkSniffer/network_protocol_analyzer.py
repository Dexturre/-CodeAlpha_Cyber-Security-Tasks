import socket
import struct
import datetime

class NetworkProtocolAnalyzer:
    """A class to demonstrate network protocol analysis concepts"""
    
    def __init__(self):
        self.protocol_map = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            2: "IGMP",
            89: "OSPF",
        }
    
    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        return self.protocol_map.get(protocol_num, f"Unknown ({protocol_num})")
    
    def analyze_sample_packets(self):
        """Analyze and display sample packet structures"""
        print("=== Network Protocol Analysis Demo ===\n")
        
        # Demonstrate IP header structure
        print("1. IP Header Structure:")
        print("   Version (4 bits) | IHL (4 bits) | Type of Service (8 bits)")
        print("   Total Length (16 bits) | Identification (16 bits)")
        print("   Flags (3 bits) | Fragment Offset (13 bits)")
        print("   Time to Live (8 bits) | Protocol (8 bits) | Header Checksum (16 bits)")
        print("   Source IP Address (32 bits)")
        print("   Destination IP Address (32 bits)")
        print("   Options (variable) | Padding (variable)")
        print()
        
        # Demonstrate TCP header structure
        print("2. TCP Header Structure:")
        print("   Source Port (16 bits) | Destination Port (16 bits)")
        print("   Sequence Number (32 bits)")
        print("   Acknowledgment Number (32 bits)")
        print("   Data Offset (4 bits) | Reserved (6 bits) | Flags (6 bits) | Window Size (16 bits)")
        print("   Checksum (16 bits) | Urgent Pointer (16 bits)")
        print("   Options (variable) | Padding (variable)")
        print()
        
        # Demonstrate UDP header structure
        print("3. UDP Header Structure:")
        print("   Source Port (16 bits) | Destination Port (16 bits)")
        print("   Length (16 bits) | Checksum (16 bits)")
        print()
        
        # Show common protocol examples
        print("4. Common Protocol Examples:")
        protocols = [
            (6, "TCP - Transmission Control Protocol", "Reliable, connection-oriented"),
            (17, "UDP - User Datagram Protocol", "Unreliable, connectionless"),
            (1, "ICMP - Internet Control Message Protocol", "Error reporting and diagnostics"),
            (2, "IGMP - Internet Group Management Protocol", "Multicast group management"),
        ]
        
        for proto_num, name, desc in protocols:
            print(f"   {proto_num}: {name}")
            print(f"     {desc}")
        print()
    
    def create_sample_packet_analysis(self):
        """Create and analyze sample packet data"""
        print("5. Sample Packet Analysis:")
        print()
        
        # Sample IP packet data (simulated)
        sample_packets = [
            {
                'source_ip': '192.168.1.100',
                'dest_ip': '8.8.8.8',
                'protocol': 17,  # UDP
                'source_port': 5353,
                'dest_port': 53,
                'payload': b'DNS query example'
            },
            {
                'source_ip': '10.0.0.5', 
                'dest_ip': '142.251.33.110',
                'protocol': 6,  # TCP
                'source_port': 49234,
                'dest_port': 443,
                'payload': b'HTTPS encrypted data'
            },
            {
                'source_ip': '172.16.0.2',
                'dest_ip': '172.16.0.1',
                'protocol': 1,  # ICMP
                'type': 8,  # Echo request
                'code': 0,
                'payload': b'ping request'
            }
        ]
        
        for i, packet in enumerate(sample_packets, 1):
            print(f"Packet {i}:")
            print(f"  Source: {packet['source_ip']}")
            print(f"  Destination: {packet['dest_ip']}")
            print(f"  Protocol: {self.get_protocol_name(packet['protocol'])}")
            
            if packet['protocol'] == 6:  # TCP
                print(f"  Source Port: {packet['source_port']}")
                print(f"  Destination Port: {packet['dest_port']}")
                print(f"  Application: HTTPS (encrypted web traffic)")
                
            elif packet['protocol'] == 17:  # UDP
                print(f"  Source Port: {packet['source_port']}")
                print(f"  Destination Port: {packet['dest_port']}")
                print(f"  Application: DNS (domain name resolution)")
                
            elif packet['protocol'] == 1:  # ICMP
                print(f"  Type: {packet['type']} (Echo Request)")
                print(f"  Code: {packet['code']}")
                print(f"  Application: Network diagnostics (ping)")
            
            print(f"  Payload: {packet['payload'][:30]}...")
            print(f"  Payload Length: {len(packet['payload'])} bytes")
            print()
    
    def demonstrate_network_concepts(self):
        """Demonstrate key network concepts"""
        print("6. Network Communication Concepts:")
        print()
        
        concepts = [
            ("Packet Switching", "Data is broken into packets that travel independently through the network"),
            ("Layered Architecture", "OSI model: Physical, Data Link, Network, Transport, Session, Presentation, Application"),
            ("IP Addressing", "Unique identifiers for devices on a network (IPv4: 32-bit, IPv6: 128-bit)"),
            ("Port Numbers", "Identify specific applications/services (0-65535)"),
            ("TCP Handshake", "Three-way handshake: SYN -> SYN-ACK -> ACK for connection establishment"),
            ("UDP Characteristics", "No handshake, no guaranteed delivery, lower overhead than TCP"),
            ("ICMP Functions", "Error reporting, network diagnostics, ping/echo requests")
        ]
        
        for concept, description in concepts:
            print(f"• {concept}:")
            print(f"  {description}")
            print()
    
    def run_demo(self):
        """Run the complete demonstration"""
        self.analyze_sample_packets()
        self.create_sample_packet_analysis()
        self.demonstrate_network_concepts()

if __name__ == "__main__":
    analyzer = NetworkProtocolAnalyzer()
    analyzer.run_demo()
