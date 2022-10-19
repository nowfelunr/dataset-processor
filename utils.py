import imp
from statistics import variance
from scapy.all import rdpcap
import numpy as np
from collections import Counter
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




def get_mean(d):
    return np.mean(d)

def get_median(d):
    return np.median(d)

def get_max(d):
    return np.max(d)

def get_most_common(d):
    counts = np.bincount(d)
    return  np.argmax(counts)

def get_variance(d):
    return np.var(d)

def get_iqr(d):
    q75, q25 = np.percentile(d, [75 ,25])
    iqr = q75 - q25

    return iqr

def get_std(d):
    return np.std(d)

def get_sum(d):
    return np.sum(d)

def get_uniq(d):
    return len(np.unique(d))
