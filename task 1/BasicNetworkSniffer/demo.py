#!/usr/bin/env python3
"""
Network Sniffer Demo Script
Demonstrates the capabilities of the Basic Network Sniffer toolkit
"""

import os
import sys

def display_banner():
    """Display a welcome banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                 BASIC NETWORK SNIFFER TOOLKIT               ║
    ║                  Educational Demonstration                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def show_menu():
    """Display the main menu"""
    print("\n📋 AVAILABLE TOOLS:")
    print("1. Network Protocol Analyzer (No admin required)")
    print("2. Packet Sniffer with Scapy (Requires admin privileges)")
    print("3. Socket-based Sniffer (Requires admin privileges)")
    print("4. View Installation Guide")
    print("5. Exit")
    
    return input("\n🎯 Select an option (1-5): ").strip()

def run_protocol_analyzer():
    """Run the educational protocol analyzer"""
    print("\n🚀 Starting Network Protocol Analyzer...")
    print("   This demo shows protocol structures without requiring special permissions")
    print("   " + "="*60)
    
    try:
        import network_protocol_analyzer
        analyzer = network_protocol_analyzer.NetworkProtocolAnalyzer()
        analyzer.run_demo()
    except Exception as e:
        print(f"❌ Error running protocol analyzer: {e}")

def run_packet_sniffer():
    """Run the Scapy-based packet sniffer"""
    print("\n🔍 Starting Packet Sniffer with Scapy...")
    print("   This requires administrative privileges and Npcap/WinPcap installation")
    print("   " + "="*60)
    
    try:
        import packet_sniffer
        print("⚠️  Note: You may need to run this as Administrator")
        print("   Capturing 5 packets (press Ctrl+C to stop earlier)...")
        packet_sniffer.start_sniffing(count=5)
    except PermissionError:
        print("❌ Permission denied. Please run as Administrator.")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure Npcap/WinPcap is installed - see INSTALLATION_GUIDE.md")

def run_socket_sniffer():
    """Run the socket-based packet sniffer"""
    print("\n🔌 Starting Socket-based Sniffer...")
    print("   This requires administrative privileges")
    print("   " + "="*60)
    
    try:
        import socket_sniffer
        print("⚠️  Note: You may need to run this as Administrator")
        socket_sniffer.start_sniffing(count=5)
    except PermissionError:
        print("❌ Permission denied. Please run as Administrator.")
    except Exception as e:
        print(f"❌ Error: {e}")

def show_installation_guide():
    """Display installation guide information"""
    print("\n📖 INSTALLATION GUIDE OVERVIEW")
    print("   " + "="*40)
    
    if os.path.exists("INSTALLATION_GUIDE.md"):
        try:
            with open("INSTALLATION_GUIDE.md", 'r', encoding='utf-8') as f:
                content = f.read()
                # Show first few lines
                lines = content.split('\n')[:15]
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        print(f"   {line}")
                print("\n   ... (see INSTALLATION_GUIDE.md for complete instructions)")
        except:
            print("   View INSTALLATION_GUIDE.md for detailed setup instructions")
    else:
        print("   Installation guide not found")

def main():
    """Main demo function"""
    display_banner()
    
    print("🎓 This toolkit helps you learn about:")
    print("   • Network protocol structures")
    print("   • Packet analysis techniques")
    print("   • How data flows through networks")
    print("   • TCP/IP protocol suite fundamentals")
    
    while True:
        choice = show_menu()
        
        if choice == '1':
            run_protocol_analyzer()
        elif choice == '2':
            run_packet_sniffer()
        elif choice == '3':
            run_socket_sniffer()
        elif choice == '4':
            show_installation_guide()
        elif choice == '5':
            print("\n👋 Thank you for using the Network Sniffer Toolkit!")
            print("   Happy learning! 🚀")
            break
        else:
            print("❌ Invalid choice. Please select 1-5.")
        
        input("\n📝 Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
