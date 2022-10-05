from scapy.all import rdpcap

# Function for getting number of packets
def get_no_of_packets(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    return len(packets)