import csv
from datetime import datetime, timedelta
import os
from time import strftime
from utils import get_no_of_packets

def get_dt_str(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")

def split_device_data_by_hour(device_type, mode):
    # capinfos -a -e test.pcap -T | awk 'FNR == 2 {print}' | awk '{print $5}'

    # editcap -A 2022-09-06T11:24:44.409677 -B 2022-09-06T12:24:44.409677  test.pcap test2.pcap

    
    pcaps_path = f'nonmedical/{device_type}'
    hourly_pcap_write_path = f'nonmedical/{device_type}/hourly_split'

    # Interaction
    csv_header = ['file_name', 'packet_count']
    csv_data = []
    for dev_no in range(1, 9):
        file_path = f'{pcaps_path}/{device_type}_{dev_no}_{mode}.pcap'
        packet_start_date = os.popen("capinfos -a -e " + file_path +" -T | awk 'FNR == 2 {print}' | awk '{print $2}'").read().strip()
        packet_start_time = os.popen("capinfos -a -e " + file_path +" -T | awk 'FNR == 2 {print}' | awk '{print $3}'").read().strip()
        packet_end_date = os.popen("capinfos -a -e " + file_path +" -T | awk 'FNR == 2 {print}' | awk '{print $4}'").read().strip()
        packet_end_time = os.popen("capinfos -a -e " + file_path +" -T | awk 'FNR == 2 {print}' | awk '{print $5}'").read().strip()

        packet_start_datetime_str = f'{packet_start_date}T{packet_start_time}'
        packet_end_datetime_str = f'{packet_end_date}T{packet_end_time}'

        packet_start_datetime = datetime.strptime(packet_start_datetime_str, "%Y-%m-%dT%H:%M:%S.%f")
        packet_end_datetime = datetime.strptime(packet_end_datetime_str, "%Y-%m-%dT%H:%M:%S.%f")

        hour_no = 1
        
        while packet_start_datetime <= packet_end_datetime:
            filter_start = get_dt_str(packet_start_datetime)

            packet_start_datetime = packet_start_datetime+timedelta(hours=1)

            filter_end = get_dt_str(packet_start_datetime)

            read_file_path = f'{pcaps_path}/{device_type}_{dev_no}_{mode}.pcap'
            write_file_path = f'{hourly_pcap_write_path}/{device_type}_{dev_no}_{str(hour_no).zfill(2)}h_{mode}.pcap'
     
            editcap_command = f'editcap -A {filter_start} -B {filter_end}  {read_file_path} {write_file_path}'

            os.popen(editcap_command).read()

            packet_count = os.popen(f'tcpdump -r {write_file_path} | wc -l').read().strip()
            csv_data.append([f'{device_type}_{dev_no}_{hour_no}h_{mode}.pcap', packet_count])

            hour_no += 1
    
    with open(f'nonmedical/{device_type}/hourly_split/{device_type}_{mode}_packet_count.csv', 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(csv_header)
        csvwriter.writerows(csv_data)








split_device_data_by_hour(device_type="plugs", mode="interaction")
split_device_data_by_hour(device_type="plugs", mode="no_interaction")