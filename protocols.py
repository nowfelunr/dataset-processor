
from utils import *
from numeric_features_filter import *
import os
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


# def get_layer(packet):
#     packet = Ether(_pkt=packet)
#     counter = 0
#     while True:
#         layer = packet.getlayer(counter)
#         if layer is None:
#             break

#         yield layer
#         counter += 1
    

# def get_packet_layers(file_path):
#     pcap = rdpcap(file_path)
#     for packet in pcap:
#         for layer in get_packet_layers(packet):
#             print (layer.name)

    


# def main():
devices = [1,2]
functionality_numbers = [3,4]
for func_no in functionality_numbers:
    for dev_no in devices:
        files = get_all_files_by_functionality(device_number=dev_no, functionality_number=func_no)
        current_device_protocols = dict()
        for pth in files:
            observed_protocols =  get_all_protocol_counts(file_path=pth,sort_by_count=True)
            for k, v in observed_protocols.items():
                if k not in current_device_protocols:
                    current_device_protocols[k] = v
                else:
                    current_device_protocols[k] += v
        
        current_device_protocols = {k: v for k, v in sorted(current_device_protocols.items(), key=lambda item: item[1], reverse=True)}        
        print(f"Functionality id : {func_no} Device No: {dev_no}")
        print(current_device_protocols)


        


# if __name__ == "__main__":
#     main()
