# light_device_mac_addresses = [
#     "78:6d:eb:bd:53:9e",
#     "78:6d:eb:bb:9a:57",
#     "78:6d:eb:ba:42:f3",
#     "78:6d:eb:bd:fd:62",
#     "78:6d:eb:bd:63:45",
#     "78:6d:eb:bb:9c:9a",
#     "78:6d:eb:bb:b3:d2",
#     "78:6d:eb:b4:a0:25",
# ]

# plug_device_mac_addresses = [
#     "70:3e:97:26:9e:fd",
#     "70:3e:97:26:ab:33",
#     "70:3e:97:2a:e2:69",
#     "70:3e:97:2a:ed:f6",
#     "70:3e:97:26:ae:61",
#     "70:3e:97:2a:e2:66",
#     "70:3e:97:27:0f:94",
#     "70:3e:97:27:d4:c9",
# ]

# camera_device_mac_addresses = [
#     "38:be:ab:ae:57:c5",
#     "38:be:ab:ae:31:d4",
#     "a4:ef:15:da:99:5a",
#     "38:be:ab:af:a1:f7",
#     "a4:ef:15:da:d0:65",
#     "38:be:ab:ae:e7:79",
#     "a4:ef:15:da:3f:32",
#     "a4:ef:15:da:6c:1b",
# ]



import os


light_device_ip_addresses = [
    "192.168.1.184",
    "192.168.1.232",
    "192.168.1.171",
    "192.168.1.204",
    "192.168.1.129",
    "192.168.1.247",
    "192.168.1.230",
    "192.168.1.191",

]

plug_device_ip_addresses = [
    "192.168.1.186",
    "192.168.1.172",
    "192.168.1.190",
    "192.168.1.120",
    "192.168.1.214",
    "192.168.1.187",
    "192.168.1.229",
    "192.168.1.185",
]

camera_device_ip_addresses = [
    "192.168.1.249",
    "192.168.1.202",
    "192.168.1.135",
    "192.168.1.130",
    "192.168.1.141",
    "192.168.1.179",
    "192.168.1.188",
    "192.168.1.117",

]

device_ip_dict = {
    'camera' : camera_device_ip_addresses,
    'lights' : light_device_ip_addresses,
    'plugs' : plug_device_ip_addresses,
}

# Split camera
def split_devices_from_pcap(device_type):
    
    interaction_file = f"nonmedical/{device_type}_interaction.pcapng"
    no_interaction_file = f"nonmedical/{device_type}_no_interaction.pcapng"
    print(no_interaction_file)
    
    # Split interactions
    dev_no = 1
    for dev_ip in device_ip_dict[device_type]:
        write_file_name = f'nonmedical/{device_type}/{device_type}_{dev_no}_interaction.pcap'
        tcpdump_command = f"tcpdump -r {interaction_file} 'host {dev_ip}' -w {write_file_name}"
        os.popen(tcpdump_command)
        dev_no += 1
    
    #Split no interactions
    dev_no = 1
    for dev_ip in device_ip_dict[device_type]:
        write_file_name = f'nonmedical/{device_type}/{device_type}_{dev_no}_no_interaction.pcap'
        tcpdump_command = f"tcpdump -r {no_interaction_file} 'host {dev_ip}' -w {write_file_name}"
        os.popen(tcpdump_command)
        dev_no += 1


# split_devices_from_pcap('camera')
# split_devices_from_pcap('lights')
split_devices_from_pcap('plugs')

