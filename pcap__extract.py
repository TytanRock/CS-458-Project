# Python3 code to Analyze the PCAP file
# files in a directory or folder 

# importing os module 
import pyshark
import pandas as pd
import numpy as np
import csv
import matplotlib.pyplot as plt
import time
import datetime
import os
import itertools


#pcap or pcapng file goes here; provide the entire path
filename = 'benign_2.pcap'


folder_sum    = "./DATA/PER_SECOND/"
folder_csv   = "./DATA/CSV/"
folder_images = "./DATA/IMAGES/"


pcap_filter = []


filter_string = "ip.addr==10.152.152.11 && tcp" # use tcp or udp filters to display appropriate traffic; you can use a combination of filters too such as --> tcp.flags.syn==1 && tcp.flags.ack==0

pcap_filter.append(filter_string)


# -------  OTHER FILTERS (EXAMPLES) ------- #

#tor : ip.addr==10.0.0.1/8 && (!icmpv6 && !mdns && !tcp.port==80) && tcp.flags.push==1
#ip.dst==131.202.240.150 && !ssl.handshake && (! tcp.analysis.retransmission) && !tcp.analysis.duplicate_ack && !icmp && !tcp.analysis.out_of_order")
#ip.dst==192.168.1.3 && ip.addr!=192.168.0.0/8  && (tcp.flags.syn==0 && tcp.flags.ack==1 && tcp.flags.fin == 0 && tcp.flags.push==1)
#ip.src==192.168.1.3 && ip.addr!=192.168.0.0/8
#push_data: ip.dst==192.168.1.3 && !ssl.handshake && tcp && !(tcp.flags.syn==1 || tcp.connection.rst || tcp.connection.fin) && !frame.len==66 
#TOR: ip.dst==10.0.2.15 && ssl.app_data 
#IoT: ip.src==192.168.0.5 && !ssl.handshake && (! tcp.analysis.retransmission) && !tcp.analysis.duplicate_ack && !icmp && !tcp.analysis.out_of_order


def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)
        exit()

createFolder(folder_csv)
createFolder(folder_images)
createFolder(folder_sum)

first_epoch    = 0.0
prev_time      = 0.0
arrival_time   = 0.0
flag            = 0
count           = 0

listoflists = []


def print_conversation_header(pkt):
    try:
        packet_length 	= pkt.captured_length
        epoch_time 		= pkt.sniff_timestamp
        delta 			= pkt.frame_info.time_delta
        number      	= pkt.number
        source_port 	= pkt[pkt.transport_layer].srcport
        dest_port  		= pkt[pkt.transport_layer].dstport
        src_ip     		= pkt.ip.src
        dst_ip			= pkt.ip.dst
        current_time   	= float(pkt.sniff_timestamp)
        human_date		= datetime.datetime.fromtimestamp(round(float(epoch_time)))
        time_relative   = pkt.tcp.time_relative
        time_delta      = pkt.tcp.time_delta
        window_size     = pkt.tcp.window_size
        window_size_scalefactor = pkt.tcp.window_size_scalefactor
        window_size_value = pkt.tcp.window_size_value
        syn_flag        = int((pkt.tcp.flags.int_value) & 0x0002 != 0)
        ack_flag        = int((pkt.tcp.flags.int_value) & 0x0010 != 0)
        res_flag        = int((pkt.tcp.flags.int_value) & 0xE000 != 0)
        push_flag       = int((pkt.tcp.flags.int_value) & 0x0080 != 0)

        no_of_packets = 1

        global flag
        global prev_time
        global arrival_time
        global first_epoch
        global listoflists
        innerList   = []


        packet_arrival_time = 0.0

        if (flag == 0):
            flag = 1
            inter_arrival_time = 0;
            prev_time = current_time;
            first_epoch = epoch_time;

        else:
            inter_arrival_time = (current_time - prev_time)*(10**3)
            prev_time = current_time



        print ("[Number]: "+ str(number) +
               " [Time]: "+ str(human_date) + 
        	" [Time]: "+ str(human_date) + 
               " [Time]: "+ str(human_date) + 
               " [Length]: "+ packet_length + 
        	" [Length]: "+ packet_length + 
               " [Length]: "+ packet_length + 
               " [Source IP]: " + str(src_ip) )
        

        float_time = float(epoch_time)
        int_time = str(round(float_time))
        innerList.append(str(int_time))
        innerList.append(packet_length)
        innerList.append(delta)
        innerList.append(no_of_packets)
        innerList.append(src_ip)
        innerList.append(dst_ip)
        innerList.append(source_port)
        innerList.append(dest_port)
        innerList.append(inter_arrival_time)
        innerList.append(time_relative)
        innerList.append(time_delta)
        innerList.append(window_size)
        innerList.append(window_size_scalefactor)
        innerList.append(window_size_value)
        innerList.append(syn_flag)
        innerList.append(ack_flag)
        innerList.append(res_flag)
        innerList.append(push_flag)
        
        listoflists.append(innerList)
        
        if float(number)%3500 == 0.0:
        	with open(folder_csv + filename.split(".")[0] + '.csv', "a") as f:
        		writer = csv.writer(f)
        		writer.writerows(listoflists)
        		listoflists = []


    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        pass

start_time = time.time()
print(start_time)


if (str(filename.split(".")[1]) == "pcap"):
    print (filename)

    with open(folder_csv + filename.split(".")[0] + '.csv', "w") as output:
        fieldnames = [#'Human Date',
        'Timestamp', 
        'Total_Packet_Length' ,
        'Delta_Time', 
        'Total_No_of_Packets', 
        'Source_IP', 'Destination_IP' ,
        'Source_Port','Dest_Port',
        'Inter_Arrival_Time',
        "Time_Relative", "Time_Delta", "window_size",
        "window_size_scalefactor", "window_size_value",
        "syn_flag" , "ack_flag", "res_flag", "push_flag"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
    cap = pyshark.FileCapture(filename , display_filter = pcap_filter[0])
    flag = 0
    cap.apply_on_packets(print_conversation_header)
else:
    print (str(filename.split(".")[1]))


with open(folder_csv + filename.split(".")[0] + '.csv', "a") as f:
    writer = csv.writer(f)
    writer.writerows(listoflists)
    listoflists = []


end_time = time.time()

print(f"TOTAL TIME TAKEN: for {filename[:11]}: {round ((end_time - start_time)/60.0, 2) } minutes" )


'''
Some information about the fields available:


	dir (pkt)
	'__class__', '__contains__', '__delattr__', '__dict__', '__dir__', 
	'__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
	 '__getitem__', '__getstate__', '__gt__', '__hash__', '__init__', 
	 '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', 
	 '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', 
	 '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_packet_string',
	  'captured_length', 'data', 'eth', 'frame_info', 'get_multiple_layers', 
	  'highest_layer', 'interface_captured', 'ip', 'layers', 'length', 'number', 
	  'pretty_print', 'show', 'sniff_time', 'sniff_timestamp', 'transport_layer', 
	  'udp'

	dir(dkt.fram_info)

	['DATA_LAYER', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', 
	'__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', 
	'__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', 
	'__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', 
	'__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', 
	'__str__', '__subclasshook__', '__weakref__', '_all_fields', '_field_prefix', 
	'_get_all_field_lines', '_get_all_fields_with_alternates', 
	'_get_field_or_layer_repr', '_get_field_repr', '_layer_name', 
	'_sanitize_field_name', 'cap_len', 'encap_type', 'field_names', 'get', 
	'get_field', 'get_field_by_showname', 'get_field_value', 'ignored', 
	'interface_id', 'interface_name', 'layer_name', 'len', 'marked', 'number', 
	'offset_shift', 'pretty_print', 'protocols', 'raw_mode', 'time', 'time_delta', 
	'time_delta_displayed', 'time_epoch', 'time_relative']



'''