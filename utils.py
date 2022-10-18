from scapy.all import rdpcap
applicable_folders = ['withing_bpm_connect_1', 'withing_bpm_connect_2']
file_extension = 'pcap'
# Function for getting number of packets
def get_no_of_packets(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    return len(packets)


def get_all_files_by_functionality(device_number, functionality_number):
    all_paths = []
    for i in range(1, 11):
        device_folder_name = applicable_folders[int(device_number)-1]
        current_iteration = str(i).zfill(2)
        device_number = str(device_number).zfill(2)
        functionality_number = str(functionality_number).zfill(2)
        full_path = f'{device_folder_name}/{device_number}_{functionality_number}_{current_iteration}.{file_extension}'
        all_paths.append(full_path)
    return all_paths
