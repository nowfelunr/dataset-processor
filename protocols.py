
from utils import *
from numeric_features_filter import *
import os

from os import listdir
from os.path import isfile, join

applicable_folders = ['withing_bpm_connect_1', 'withing_bpm_connect_2']
# cap = pyshark.FileCapture('withing_bpm_connect_1/01_02_03.pcap')

file_extension = "pcap"

# protocol_count = dict()
# for pkt in cap:
#     current_protocol = str(pkt.highest_layer)
#     if current_protocol in protocol_count:
#         protocol_count[current_protocol] += 1
#     else:
#         protocol_count[current_protocol] = 1

# print(protocol_count)


def get_all_protocol_counts(file_path, sort_by_count=False):
    tshark_command = f"tshark -Tfields -eframe.protocols -r {file_path}"
    protocol_count = dict()
    resp = os.popen(tshark_command).read()
    protocols = resp.split('\n')

    for proto in protocols:
        current_protocol = proto.split(":")[-1]
        if current_protocol == '':
            continue
        if current_protocol in protocol_count:
            protocol_count[current_protocol] += 1
        else:
            protocol_count[current_protocol] = 1
    if sort_by_count:
        protocol_count = {k: v for k, v in sorted(protocol_count.items(), key=lambda item: item[1], reverse=True)}
    return protocol_count



# devices = [1,2]
# functionality_numbers = [3,4]
# for func_no in functionality_numbers:
#     for dev_no in devices:
#         files = get_all_files_by_functionality(device_number=dev_no, functionality_number=func_no)
#         current_device_protocols = dict()
#         for pth in files:
#             observed_protocols =  get_all_protocol_counts(file_path=pth,sort_by_count=True)
#             for k, v in observed_protocols.items():
#                 if k not in current_device_protocols:
#                     current_device_protocols[k] = v
#                 else:
#                     current_device_protocols[k] += v
        
#         current_device_protocols = {k: v for k, v in sorted(current_device_protocols.items(), key=lambda item: item[1], reverse=True)}        
#         print(f"Functionality id : {func_no} Device No: {dev_no}")
#         print(current_device_protocols)


def get_all_protocols(file_path):
    tshark_command = f"tshark -Tfields -eframe.protocols -r {file_path}"
    all_protocols = []
    resp = os.popen(tshark_command).read()
    protocols = resp.split('\n')

    for proto in protocols:
        current_protocol = proto.split(":")[-1]
        if current_protocol == '':
            continue
        if not current_protocol in all_protocols:
            all_protocols.append(current_protocol)
       
    return all_protocols

def get_aggregated_protocols():
    aggregated_protocol = []
    all_files = [f for f in listdir("aggregated_data/") if isfile(join("aggregated_data/", f))]
    total_file = len(all_files)
    for f in all_files:
        print(total_file)
        total_file -= 1
        aggregated_protocol.extend(get_all_protocols(f'aggregated_data/{f}'))

    return set(aggregated_protocol)

print("\n\n\n")
print(get_aggregated_protocols())
# print(get_all_protocols("nonmedical/plugs/hourly_split/plugs_8_25h_no_interaction.pcap"))


# if __name__ == "__main__":
#     main()
