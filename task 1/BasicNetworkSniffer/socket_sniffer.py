import socket
import struct
import datetime

def create_raw_socket():
    """Create a raw socket to capture packets"""
    try:
        # Create raw socket for IP packets
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(('0.0.0.0', 0))
        
        # Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Enable promiscuous mode
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        return s
    except Exception as e:
        print(f"Error creating socket: {e}")
        return None

def parse_ip_header(data):
    """Parse IP header from raw packet data"""
    # Unpack IP header (20 bytes)
    ip_header = data[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    return {
        'version': version,
        'header_length': iph_length,
        'ttl': ttl,
        'protocol': protocol,
        'source_ip': s_addr,
        'dest_ip': d_addr,
        'data': data[iph_length:]
    }

def get_protocol_name(protocol_num):
    """Map protocol numbers to names"""
    protocol_map = {
        1: "ICMP",
        6: "TCP", 
        17: "UDP",
        2: "IGMP",
        89: "OSPF",
        # Add more protocols as needed
    }
    return protocol_map.get(protocol_num, f"Unknown ({protocol_num})")

def parse_tcp_header(data):
    """Parse TCP header from data"""
    if len(data) < 20:
        return None
    
    tcp_header = data[:20]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    
    return {
        'source_port': tcph[0],
        'dest_port': tcph[1],
        'sequence': tcph[2],
        'acknowledgment': tcph[3],
        'data_offset': (tcph[4] >> 4) * 4,
        'flags': tcph[5] & 0x3F
    }

def parse_udp_header(data):
    """Parse UDP header from data"""
    if len(data) < 8:
        return None
    
    udp_header = data[:8]
    udph = struct.unpack('!HHHH', udp_header)
    
    return {
        'source_port': udph[0],
        'dest_port': udph[1],
        'length': udph[2],
        'checksum': udph[3]
    }

def analyze_packet(packet_data):
    """Analyze and display packet information"""
    ip_info = parse_ip_header(packet_data)
    
    print(f"\n=== Packet Captured at {datetime.datetime.now()} ===")
    print(f"Source IP: {ip_info['source_ip']}")
    print(f"Destination IP: {ip_info['dest_ip']}")
    print(f"Protocol: {get_protocol_name(ip_info['protocol'])} ({ip_info['protocol']})")
    print(f"TTL: {ip_info['ttl']}")
    
    # Analyze transport layer
    if ip_info['protocol'] == 6:  # TCP
        tcp_info = parse_tcp_header(ip_info['data'])
        if tcp_info:
            print(f"Source Port: {tcp_info['source_port']}")
            print(f"Destination Port: {tcp_info['dest_port']}")
            print(f"TCP Flags: {tcp_info['flags']:06b}")
            
    elif ip_info['protocol'] == 17:  # UDP
        udp_info = parse_udp_header(ip_info['data'])
        if udp_info:
            print(f"Source Port: {udp_info['source_port']}")
            print(f"Destination Port: {udp_info['dest_port']}")
            print(f"UDP Length: {udp_info['length']}")
    
    # Show payload information
    payload = ip_info['data']
    if len(payload) > 0:
        print(f"Payload Length: {len(payload)} bytes")
        if len(payload) > 50:
            print(f"Payload Preview: {payload[:50]}")
            try:
                decoded = payload.decode('utf-8', errors='ignore')
                if decoded.strip():
                    print(f"Decoded: {decoded[:100]}...")
            except:
                print("Payload contains binary data")
    
    print(f"Total Packet Length: {len(packet_data)} bytes")
    print("=" * 50)

def start_sniffing(count=10):
    """Start packet sniffing"""
    sock = create_raw_socket()
    if not sock:
        print("Failed to create socket. Try running as Administrator.")
        return
    
    print("Starting packet capture...")
    print("Press Ctrl+C to stop\n")
    
    try:
        packets_captured = 0
        while count == 0 or packets_captured < count:
            packet = sock.recvfrom(65565)[0]
            analyze_packet(packet)
            packets_captured += 1
            
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
        except:
            pass

if __name__ == "__main__":
    # Capture 10 packets
    start_sniffing(count=10)
