from utils  import *
import csv 

# Search Folders
applicable_folders = ['withing_bpm_connect_1', 'withing_bpm_connect_2']

# File Extension
file_extension = "pcap"


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
        


def get_all_individual_measurements(device_number, functionality_number):
    device_folder_name = applicable_folders[device_number-1]
    
    response = []
    for i in range(1, 11):
        packets = 0
        current_iteration = str(i).zfill(2)
        device_number = str(device_number).zfill(2)
        functionality_number = str(functionality_number).zfill(2)
        full_path = f'{device_folder_name}/{device_number}_{functionality_number}_{current_iteration}.{file_extension}'
        try:
            packets = get_no_of_packets(full_path)
        except Exception as e:
            # print("Error reading: " + full_path)
            # print(str(e))
            pass
        finally:
            response.append(packets)
        
    return response


        




def main():
    functionality_numbers = [1,2,3,4,9,10,12,15]
    csv_list = []
    csv_header = ["Device No", "Function No", "Avg Packet"]
    for i in range(1, 11):
        csv_header.append(f"Measurement {i}")
    for device_number in range(1, 3):
        for functionality_number in functionality_numbers:
            avg_packet = get_avg_packet(device_number=device_number, functionality_number=functionality_number)
            # print(f'Device No: {device_number} Func No: {functionality_number} Avg: {avg_packet}')
            current_csv = [device_number, functionality_number, avg_packet]
            individual_measurements = get_all_individual_measurements(device_number, functionality_number)

            current_csv.extend(individual_measurements)
            csv_list.append(current_csv)
    
    with open('functionality_measurement_details.csv', 'w') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(csv_header)
        csv_writer.writerows(csv_list)
    print(csv_list)



if __name__ == "__main__":
    main()