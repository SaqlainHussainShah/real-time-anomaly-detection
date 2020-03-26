""" 
Following command listens to any connection available and save in pcap file
		
		sudo tcpdump -i any -w web.pcap

	This Python file extracts features from pcap file and save them to csv format
	Types of features:
		TCP
		IP addresses
"""


import scapy
from scapy.all import *

import pandas as pd

packets=rdpcap('./web.pcap')

print(len(packets))
# print((packets[3]['TCP']).show())
# # print(packets[3].proto)
# # print(packets[3].show())
# print(packets[3]['TCP'].options[2][1])
# # for label in packets[3]['TCP'].show():
# # 	print(label , " value is : ")
# # print(packets[3]['TCP'].show())

list_of_all_dictionaries=[]

for i in range(len(packets)):

	dictionary_of_data={}
	pkt=packets[i]

	# Features from IP
	try :
		dictionary_of_data['sender_ip']				=	pkt['IP'].src
		dictionary_of_data['destination_ip']		=	pkt['IP'].dst
		dictionary_of_data['protocol_ip']			=	pkt['IP'].proto
		dictionary_of_data['length']				=	pkt['IP'].len
	except:
		continue	# Features from TCP
	try:
		dictionary_of_data['source_port']			=	pkt['TCP'].sport
		dictionary_of_data['destination_port']		=	pkt['TCP'].dport
		dictionary_of_data['data_of_s']				=	pkt['TCP'].dataofs
		dictionary_of_data['seq']					=	pkt['TCP'].seq
		dictionary_of_data['ack']					=	pkt['TCP'].ack
		dictionary_of_data['flags']					=	pkt['TCP'].flags
		dictionary_of_data['window']				=	pkt['TCP'].window
		dictionary_of_data['chksum']				=	pkt['TCP'].chksum
		dictionary_of_data['urgptr']				=	pkt['TCP'].urgptr
		dictionary_of_data['start_time']			=	pkt['TCP'].options[2][1][0]
		dictionary_of_data['end_time']				=	pkt['TCP'].options[2][1][1]

		list_of_all_dictionaries.append(dictionary_of_data)		# Only store data if TCP data is available

	except:
		continue


print(len(list_of_all_dictionaries))

df=pd.DataFrame(list_of_all_dictionaries)
df.to_csv('web_tcp_ip.csv')