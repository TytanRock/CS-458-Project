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
        'Inter_Arrival_Time'])

    grouped = df.groupby('Timestamp')

    save__sum__dir = folder__sum  + "/" + name +".csv"
    save__image__dir = folder__images + name + ".png"
    

    # print (dir (grouped))
    grouped.sum().reset_index().to_csv( save__sum__dir,index=False)
    
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

    
