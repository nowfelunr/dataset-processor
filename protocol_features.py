import csv
from operator import le
from re import U
from statistics import mean
from traceback import print_tb
from utils import *
import os
import json
from numeric_features_filter import *
import numpy as np
import csv
from typepy import Integer, TypeConversionError

from os import listdir
from os.path import isfile, join

applicable_folders = ['withing_bpm_connect_1', 'withing_bpm_connect_2']
# cap = pyshark.FileCapture('withing_bpm_connect_1/01_02_03.pcap')

file_extension = "pcap"
# tcp_protocol_features = 
# tls_protocol_features = 
# arp_protocol_features = 
# dhcp_protocol_features =

# ['arp', 'coap', 'data', 'data-text-lines', 'dhcp', 'dns', 'eth', 'ethertype', 'http', 'icmp', 'ip', 'llc', 'pkix1explicit', 'pkix1implicit', 'tcp', 'tls', 'udp', 'x509ce', 'x509sat']
    
devices = [1,2]
functionality_numbers = [1,2,3,4,9,10,12,15]


all_protocols =  ['arp', 'coap', 'data', 'dhcp', 'dns', 'eth', 'http', 'icmp', 'ip', 'llc', 'pkix1explicit', 'pkix1implicit', 'tcp', 'tls', 'udp', 'x509ce', 'x509sat']
ten_features = ['median', 'mean', 'max', 'mostcommon', 'variance', 'iqr', 'std', 'sum', 'uniq']

protocol_feature_map = {
    "arp" : get_tshark_valid_arp_protocol_feature_list(),
    "coap" : get_tshark_valid_coap_protocol_feature_list(),
    "data" : get_tshark_valid_data_protocol_feature_list(),
    "dhcp" :  get_tshark_valid_dhcp_protocol_feature_list(),
    "dns" : get_tshark_valid_dns_protocol_feature_list(),
    "eth" : get_tshark_valid_eth_protocol_feature_list(),
    # "ethertype" : get_tshark_valid_ethertype_protocol_feature_list(),
    "http" : get_tshark_valid_http_protocol_feature_list(),
    "icmp" : get_tshark_valid_icmp_protocol_feature_list(),
    "ip" : get_tshark_valid_ip_protocol_feature_list(),
    "llc" : get_tshark_valid_llc_protocol_feature_list(),
    "pkix1explicit" : get_tshark_valid_pkix1explicit_protocol_feature_list(),
    "pkix1implicit" : get_tshark_valid_pkix1implicit_protocol_feature_list(),
    "tcp" : get_tshark_valid_tcp_protocol_feature_list(),
    "tls" : get_tshark_valid_tls_protocol_feature_list(),
    "udp" : get_tshark_valid_udp_protocol_feature_list(),
    "x509ce" : get_tshark_valid_x509ce_protocol_feature_list(),
    "x509sat" : get_tshark_valid_x509sat_protocol_feature_list(), 

}

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
        # try:
        current_data = []
        current_data.append(packet_no)
        for proto in protocol_features:
            
            val = d.get('_source', None).get('layers', None).get(proto, None)
            # val = 0 if val is None else int(val[0])
            val = "0" if val is None else val[0]
            if "-" in val:
                val = "0"
            if "x" in val:
                val = int(val[0], 16)
            else:
                # print(val[0])
                val = int(val[0])
            current_data.append(val)

        
        extracted_data.append(current_data)

        packet_no += 1
        # except Exception as e:
        #     print(str(e))
    # print(extracted_data)
    return extracted_data

                



def write_file(filename,protocol, data):
    csv_headers = ['packet_no']
    protocol_features = protocol_feature_map[protocol]
    csv_headers.extend(protocol_features)
    # if protocol == 'tcp':
    #     csv_headers.extend(tcp_protocol_features)
    #     protocol_features = tcp_protocol_features
    # if protocol == 'tls':
    #     csv_headers.extend(tls_protocol_features)
    #     protocol_features = tls_protocol_features
    # if protocol == 'arp':
    #     csv_headers.extend(arp_protocol_features)
    #     protocol_features = arp_protocol_features
    # if protocol == 'dhcp':
    #     csv_headers.extend(dhcp_protocol_features)
    #     protocol_features = dhcp_protocol_features
    
    # print(process_feature_json(json_data=data, protocol_features=protocol_features))
    
    with open(f'{protocol}/{filename}.csv', 'w') as f:
        csvwriter = csv.writer(f)
        csvwriter.writerow(csv_headers)
        csvwriter.writerows(process_feature_json(json_data=data, protocol_features=protocol_features))



def extract_numeric_features():

    for func_no in functionality_numbers:
        for dev_no in devices:
            files = get_all_files_by_functionality(device_number=dev_no, functionality_number=func_no)   
            for file in files:
                file_name = file.split('/')[-1]
                file_name = file_name.split('.')[0]

                for proto in all_protocols:
                    data = command_exec(file, protocol_feature_map[proto])
                    write_file(filename=file_name, protocol=proto, data=data)
                
                # tcp_data = command_exec(file, tcp_protocol_features)
                # tls_data = command_exec(file, tls_protocol_features)
                # arp_data  = command_exec(file, arp_protocol_features)
                # dhcp_data = command_exec(file, dhcp_protocol_features)
                # write_file(filename=file_name, protocol="tls", data=tls_data)
                # write_file(filename=file_name, protocol='tcp', data=tcp_data)
                # write_file(filename=file_name, protocol='arp', data=arp_data)
                # write_file(filename=file_name, protocol='dhcp', data=dhcp_data)






def get_csv_header(protocol):
    csv_header = []
    for feature in protocol_feature_map[protocol]:
        current_feature_header = []
        for ten_feat in ten_features:
            title = f'{feature}_{ten_feat}'
            current_feature_header.append(title)
        csv_header.extend(current_feature_header)
    
    return csv_header


def get_ten_stat_of_protocol(file, protocol):
    data = command_exec(file, protocol_feature_map[protocol])
    # print(protocol)
    d = process_feature_json(data, protocol_feature_map[protocol])
    d = np.array(d)
    # file_name = file.split('/')[-1]
    # file_name = file_name.split('.')[0]
    current_feature_data = []
    if len(d) == 0:
        print(f'{file} {protocol} len 0')
        return [0 for _ in range(10)]
    for i in range(0, len(protocol_feature_map[protocol])):
        curr_col = d[:, i+1]
        mean = get_mean(curr_col)
        median = get_median(curr_col)
        mx = get_max(curr_col)
        most_common = get_most_common(curr_col)
        variance = get_variance(curr_col)
        iqr = get_iqr(curr_col)
        std = get_std(curr_col)
        sum = get_sum(curr_col)
        uniq = get_uniq(curr_col)

        tmd_d = [median, mean, mx, most_common, variance, iqr, std, sum, uniq]
        current_feature_data.extend(tmd_d)
    
    return current_feature_data
    

# def generate_ten_matrices():
#     csv_file = open("features.csv", 'w')
#     csv_header = ["file_name"]
                
#     csv_writer = csv.writer(csv_file)
#     for protocol in all_protocols:
#         csv_header.extend(get_csv_header(protocol))


#     # Write the header for csv containing all the columns  
#     csv_writer.writerow(csv_header)
    
#     files  = [f for f in listdir("aggregated_data/") if isfile(join("aggregated_data/", f))]
#     total_files = len(files)
#     for file in files: 
#         file = join("aggregated_data/", file)
        
#         file_name = file.split('/')[-1]
#         file_name = file_name.split('.')[0]
#         current_csv_row = [file_name]
#         for protocol in all_protocols:
#             current_file_ten_metrics = get_ten_stat_of_protocol(file, protocol)
#             current_csv_row.extend(current_file_ten_metrics)

#             # tmd_d = [median, mean, mx, most_common, variance, iqr, std, sum, uniq]
#             # current_feature_data.extend(tmd_d)

#         csv_writer.writerow(current_csv_row)
#         print(f'{file} done')
#         print(total_files)
#         total_files -= 1
#         # break
    
      
def generate_ten_matrices():
    csv_file = open("features.csv", 'w')
    csv_header = ["file_name"]
                
    csv_writer = csv.writer(csv_file)
    for protocol in all_protocols:
        csv_header.extend(get_csv_header(protocol))


    # Write the header for csv containing all the columns  
    csv_writer.writerow(csv_header)
    
    files  = [f for f in listdir("aggregated_data/") if isfile(join("aggregated_data/", f))]
    total_files = len(files)
    for file in files: 
        file = join("aggregated_data/", file)
        
        file_name = file.split('/')[-1]
        file_name = file_name.split('.')[0]
        current_csv_row = [file_name]
        for protocol in all_protocols:
            current_file_ten_metrics = get_ten_stat_of_protocol(file, protocol)
            current_csv_row.extend(current_file_ten_metrics)

            # tmd_d = [median, mean, mx, most_common, variance, iqr, std, sum, uniq]
            # current_feature_data.extend(tmd_d)

        csv_writer.writerow(current_csv_row)
        print(f'{file} done')
        print(total_files)
        total_files -= 1
        # break
                    

    
generate_ten_matrices()


# for proto in all_protocols:
#     print(get_ten_stat_of_protocol('aggregated_data/lights_6_09h_no_interaction.pcap', proto))
