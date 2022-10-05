
from scapy.all import rdpcap

# Search Folders
applicable_folders = ['withing_bpm_connect_1', 'withing_bpm_connect_2']

# File Extension
file_extension = "pcap"


# Function for getting number of packets
def get_no_of_packets(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    return len(packets)


# Function for generating average packets
def get_avg_packet(device_number, functionality_number):
    device_folder_name = applicable_folders[device_number-1]
    total_packets = 0
    total_file_count = 0
    for i in range(1, 11):
        current_iteration = str(i).zfill(2)
        device_number = str(device_number).zfill(2)
        functionality_number = str(functionality_number).zfill(2)
        full_path = f'{device_folder_name}/{device_number}_{functionality_number}_{current_iteration}.{file_extension}'
        try:
            packets = get_no_of_packets(full_path)
            total_packets += packets
            total_file_count += 1
        except Exception as e:
            # print("Error reading: " + full_path)
            # print(str(e))
            pass
    
    if total_file_count != 0:
        avg_packet = total_packets / total_file_count
    else:
        avg_packet = 0

    return int(avg_packet)
        


functionality_numbers = [1,2,3,4,9,10,12,15]

for device_number in range(1, 3):
    for functionality_number in functionality_numbers:
        avg_packet = get_avg_packet(device_number=device_number, functionality_number=functionality_number)
        print(f'Device No: {device_number} Func No: {functionality_number} Avg: {avg_packet}')