Python Network Sniffer
A simple, cross-platform network packet sniffer written in pure Python. It captures raw network traffic and pretty-prints Ethernet frames along with the encapsulated IPv4, TCP, UDP, and ICMP packets directly to your terminal.

**Features**
Ethernet frame parsing — source/destination MAC addresses and EtherType

IPv4 packet decoding — version, header length, TTL, protocol, source/target IP

Protocol dissection for:

ICMP (type, code, checksum)

TCP (ports, sequence/ack numbers, flags)

UDP (ports, size)

Multi-line hex dump of payload data

**Cross-platform support:**

Linux — uses AF_PACKET raw sockets

Windows — uses AF_INET + SIO_RCVALL (raw socket promiscuous mode)

Graceful shutdown on Ctrl+C

**Requirements**
Python 3.6+

Root/Administrator privileges (raw sockets require elevated permissions)

No third-party libraries — only the standard library (socket, struct, textwrap, sys)

**Usage**
Linux
bash
sudo python3 sniffer.py
Windows (run as Administrator)
powershell
python sniffer.py
On Windows you must open an elevated Command Prompt / PowerShell, otherwise ioctl(SIO_RCVALL, ...) will fail with PermissionError.

Press Ctrl+C to stop sniffing. On Windows the RCVALL mode is disabled and the socket closed cleanly.

**How It Works**
A raw socket is opened (platform-specific setup).

Packets are read in a loop with recvfrom(65536).

ethernet_frame() unpacks the 14-byte Ethernet header.

If the EtherType is 0x0800 (IPv4), the payload is decoded by ipv4_packet().

The protocol field determines whether the payload is handed to icmp_packet(), tcp_segment(), or udp_segment().

Results are printed using tab-indented, multi-line formatting.

**Function overview
Function	Purpose**
main()	Opens socket, loops, dispatches packets
ethernet_frame(data)	Unpacks MAC addresses + EtherType
get_mac_addr(bytes)	Formats 6 bytes as AA:BB:CC:DD:EE:FF
ipv4_packet(data)	Unpacks IPv4 header fields
ipv4(addr)	Formats 4 bytes as dotted IPv4
icmp_packet(data)	Unpacks ICMP header
tcp_segment(data)	Unpacks TCP header + flags
udp_segment(data)	Unpacks UDP header
format_multi_line(prefix, string)	Hex-dumps bytes with wrapping
handle_ipv4(data) / handle_ipv4_raw(data)	Protocol dispatch for Linux / Windows
dispatch_protocol(proto, data)	Routes to ICMP/TCP/UDP handlers
**Sample Output**
text
Ethernet Frame:
     - Destination: 3C:52:82:1A:2B:3C, Source: A4:5E:60:XX:XX:XX, Protocol: 8
     - IPv4 Packet:
             - Version: 4, Header Length: 20, TTL: 64
             - Protocol: 6, Source: 192.168.1.10, Target: 93.184.216.34
     - TCP Segment:
             - Source Port: 52142, Destination Port: 443
             - Sequence: 2891234, Acknowledgment: 0
             - Flags:
                     - URG: 0, ACK: 0, PSH: 0, RST: 0, SYN: 1, FIN: 0
        \x00\x00\x00\x00...  (payload hex)
**Notes & Limitations**
Linux only for full Ethernet capture. On Windows, the AF_INET raw socket begins at the IP layer, so there is no MAC address or EtherType — the code handles this via handle_ipv4_raw().

No IP header on Windows? Windows returns the IP packet with the header included, so ipv4_packet() is still used directly on the raw buffer.

No packet filtering — every packet on the interface is printed. On busy networks this will flood your terminal; pipe to a file or add BPF-style filters as needed.

Not optimized for performance — Python-level packet parsing is fine for learning and diagnostics, but not for high-throughput capture (use tcpdump / Wireshark for production work).

IPv6 is not supported — only IPv4 (EtherType == 0x0800) is decoded.

Fragmented IP packets and non-first fragments are not reassembled.

**Troubleshooting**
Symptom	Cause / Fix
PermissionError / OSError: [Errno 1]	Not running as root/Administrator
AttributeError: module 'socket' has no attribute 'AF_PACKET'	You're on Windows — use the Windows branch
struct.error: unpack requires a buffer of ...	Truncated packet; usually harmless on loopback
Nothing printed	Wrong interface, or no traffic; try pinging from another terminal
ioctl fails on Windows	Ensure IP_HDRINCL is set and you're elevated
**Educational Purpose**
This project is intended as a learning tool for understanding packet structure and Python's struct module. Only run it on networks you own or have explicit permission to monitor — capturing traffic on networks you don't control may be illegal in your jurisdiction.
