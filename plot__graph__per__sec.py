import itertools
import csv
import matplotlib.pyplot as plt
import os
import numpy as np
import collections
import math
import matplotlib.cm as cm
import pylab as pl
import pandas as pd
import datetime as dt



folder__sum    = "./DATA/PER_SECOND/"
folder__csv   = "./DATA/CSV/"
folder__images = "./DATA/IMAGES/"



#loop thru the all the CSV files in the CSV directory
for fcount, filename in enumerate(os.listdir(folder__csv)):
    if (fcount == 11):
        break
    if not (os.path.isfile(folder__csv + filename)):
        print(os.path.exists(folder__csv))
        continue

    name = filename.split(".csv")[0]

    pat             = []
    time__delta     = []
    length          = []
    iat             = []
    no_of_packets   = []
    srcp            = []
    dstp            = []
    time_relative   = []
    time_delta      = []
    window_size     = []

    count           = 0

    i               = []
    
    
    #filename = "12_07_16_57__normal__operation.csv"
    df = pd.read_csv( folder__csv + filename, header=1, names=[
        'Timestamp', 
        'Total_Packet_Length',
        'Delta_Time', 
        'Total_No_of_Packets', 
        'Source_IP', 
        'Destination_IP' ,
        'Source_Port',
        'Dest_Port',
		'Inter_Arrival_Time',
        "Time_Relative", "Time_Delta", "window_size",
        "window_size_scalefactor", "window_size_value",
        "syn_flag", "ack_flag", "res_flag", "push_flag"])

    # Calculate entropy of ports
    src_port_entropy = []
    dst_port_entropy = []
    packet_count = 0
    last_timestamp = df["Timestamp"][0]
    src_port_calculation = {}
    dst_port_calculation = {}
    total = len(df.index)
    for index, row in df.iterrows():
        packet_count += 1 # Increment packet count for new packet
        src_port = row["Source_Port"]
        if not src_port in src_port_calculation:
            src_port_calculation[src_port] = 0
        src_port_calculation[src_port] += 1
        dst_port = row["Source_Port"]
        if not dst_port in dst_port_calculation:
            dst_port_calculation[dst_port] = 0
        dst_port_calculation[dst_port] += 1
        if row["Timestamp"] != last_timestamp or (index + 1) == total:
            last_timestamp = row["Timestamp"]
            src_port_entropy_tmp = 0
            dst_port_entropy_tmp = 0
            for key, p in src_port_calculation.items():
                src_port_entropy_tmp += -(p / packet_count) * math.log2(p / packet_count)
            for key, p in dst_port_calculation.items():
                dst_port_entropy_tmp += -(p / packet_count) * math.log2(p / packet_count)
            packet_count = 0
            src_port_calculation = {}
            dst_port_calculation = {}
            src_port_entropy.append(src_port_entropy_tmp)
            dst_port_entropy.append(dst_port_entropy_tmp)


    grouped = df.groupby('Timestamp')

    save__sum__dir = folder__sum  + "/" + name +".csv"
    save__image__dir = folder__images + name + ".png"
    

    # print (dir (grouped))
    newframe = grouped.sum()
    newframe["src_port_entropy"] = src_port_entropy
    newframe["dst_port_entropy"] = dst_port_entropy
    newframe.reset_index().to_csv( save__sum__dir,index=False)
    
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(filename)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")

        
    with open(save__sum__dir, 'r') as dataFile:
        csv_reader = csv.reader(dataFile)
        next(csv_reader)
        for count, row in enumerate(csv_reader):
            length.append(float(row[1])/1000)
            no_of_packets.append(float(row[3]))
            iat.append((float(row[6])/float(row[3])) )
            print ("[Timestamp]: "   + str(row[0]) + 
            " [No of packets]: " + str(no_of_packets[count]) +
            " [Length]: "       + str(row[1]))

    
    #### scattered plot graph ####
    figure1 = plt.figure(1)

    # plot the bitrate and inter-arrival time per second in a subplot

    sub1Dot = plt.subplot(211)
    sub1Dot.set_title(name, fontsize=18, weight='bold')
    xmin, xmax = 0, 60
    ymin,ymax = 0, 2500
    axes = plt.gca()
    #axes.set_xlim([xmin,xmax])
    #axes.set_ylim([ymin,ymax])
    #plt.axis("off")
    #plt.plot(length, 'o', markersize = 2, label = 'dst', color = (1,0,0))
    #plt.title(name, fontsize=14, weight='bold');
    plt.plot( length, '-', markersize = 2, label = 'dst', color='b')
    plt.grid()
    plt.xlabel('Time (s)', fontsize=14, weight='bold')
    plt.ylabel('Packet length (KBytes)', fontsize=14, weight='bold')

    sub1Dot = plt.subplot(212)
    #sub1Dot.set_title(name, fontsize=18, weight='bold')
    xmin, xmax = 0, 60
    ymin,ymax = 0, 5
    axes = plt.gca()
    #axes.set_xlim([xmin,xmax])
    #axes.set_ylim([ymin,ymax])
    plt.plot(iat, '-', markersize = 2, label = 'dst', color = (0,0,1))
    plt.grid()
    plt.xlabel('Time (s)', fontsize=14, weight='bold')
    plt.ylabel('Inter-arrival Time (ms)', fontsize=14, weight='bold')



    figure1.set_size_inches(23.5, 13.2 , forward=True)
    plt.show()
    figure1.savefig(save__image__dir ) #, bbox_inches='tight', pad_inches = 0

    # to save as pdf    
    # from matplotlib.backends.backend_pdf import PdfPages
    # pp = PdfPages(folder__pdf + name + plot__type +'.pdf')
    # pp.savefig(figure1)
    # pp.close()
    
    axes.cla()
    figure1.clf()

    
