import csv
from re import U
from utils import *
import os
import json
from numeric_features_filter import *
import csv
applicable_folders = ['withing_bpm_connect_1', 'withing_bpm_connect_2']
# cap = pyshark.FileCapture('withing_bpm_connect_1/01_02_03.pcap')

file_extension = "pcap"
tcp_protocol_features = get_tshark_valid_tcp_protocol_feature_list()
tls_protocol_features = get_tshark_valid_tls_protocol_feature_list()
arp_protocol_features = get_tshark_valid_arp_protocol_feature_list()
dhcp_protocol_features = get_tshark_valid_dhcp_protocol_feature_list()

def command_exec(file_path, feature_list):
    tshark_command = f"tshark -r {file_path} -T json "
    for fet in feature_list:
        tshark_command += f' -e {fet}'
    # print(tshark_command)
    resp = os.popen(tshark_command).read()
    resp = resp.replace("\n", "")
    json_resp = json.loads(resp)
    return json_resp

    





def process_feature_json(json_data, protocol_features):
    packet_no = 1
    extracted_data = []
    for d in json_data:
        current_data = dict()
        try:
            current_data = []
            current_data.append(packet_no)
            for proto in protocol_features:
                
                val = d.get('_source', None).get('layers', None).get(proto, None)
                current_data.append(None if val is None else val[0])

            
            extracted_data.append(current_data)

            packet_no += 1
        except:
            pass 
    # print(extracted_data)
    return extracted_data

                
    
devices = [1,2]
functionality_numbers = [3,4,15]


csv_rows = []






def write_file(filename,protocol, data):
    csv_headers = ['packet_no']
    if protocol == 'tcp':
        csv_headers.extend(tcp_protocol_features)
        protocol_features = tcp_protocol_features
    if protocol == 'tls':
        csv_headers.extend(tls_protocol_features)
        protocol_features = tls_protocol_features
    if protocol == 'arp':
        csv_headers.extend(arp_protocol_features)
        protocol_features = arp_protocol_features
    if protocol == 'dhcp':
        csv_headers.extend(dhcp_protocol_features)
        protocol_features = dhcp_protocol_features
    
    # print(process_feature_json(json_data=data, protocol_features=protocol_features))
    
    with open(f'{protocol}/{filename}.csv', 'w') as f:
        csvwriter = csv.writer(f)
        csvwriter.writerow(csv_headers)
        csvwriter.writerows(process_feature_json(json_data=data, protocol_features=protocol_features))





for func_no in functionality_numbers:
    for dev_no in devices:
        files = get_all_files_by_functionality(device_number=dev_no, functionality_number=func_no)   
        for file in files:
            file_name = file.split('/')[-1]
            file_name = file_name.split('.')[0]
            
            tcp_data = command_exec(file, tcp_protocol_features)
            tls_data = command_exec(file, tls_protocol_features)
            arp_data  = command_exec(file, arp_protocol_features)
            dhcp_data = command_exec(file, dhcp_protocol_features)
            write_file(filename=file_name, protocol="tls", data=tls_data)
            write_file(filename=file_name, protocol='tcp', data=tcp_data)
            write_file(filename=file_name, protocol='arp', data=arp_data)
            write_file(filename=file_name, protocol='dhcp', data=dhcp_data)

    #         break   
    #     break
    # break
           


            


# print(tcp_protocol_features)
# j = command_exec("withing_bpm_connect_1/01_03_03.pcap", tcp_protocol_features )[50]
# print(j.get('_source', None).get('layers', None).get('tcp.srcport', None))

# if __name__ == "__main__":
#     main()
