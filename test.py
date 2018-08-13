#!/usr/bin/python
# -*- coding: utf-8 -*-

## Created By.Farid Arjmand ##

import pcapy
import sys
import os
import getopt
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP
from time import strftime
from time import sleep

##############################
########## Variable ##########
##############################

#dev = "eth0"
dev = "wlp3s0"
dump_file = strftime("%Y-%m-%d-%H.pcap")
tmp_file = "tmp.pcap"

packet_limit = 100
max_bytes = 1024
promiscuous = False
read_timeout = 0

###############################
########## Functions ##########
###############################

def write_packet(hdr, data):
	#print decoder.decode(data)
	dumper.dump(hdr, data)

def read_packet(hdr, data):
	ether = decoder.decode(data)
	if ether.get_ether_type() == IP.ethertype:
  		iphdr = ether.child()
  		#tcphdr = iphdr.child()
  		DES = iphdr.get_ip_dst()
  		SRC = iphdr.get_ip_src()
  		#DESP = str(tcphdr.get_th_dport())
  		#SRCP = str(tcphdr.get_th_sport())
		file = open("out.txt","a+")
		file.write(DES); file.write("\n")
                file.write(SRC); file.write("\n")
		file.close()

def check():
	if(os.getuid() or os.geteuid()):
		print ("Requires root access")
		exit (1)
	if not dev in pcapy.findalldevs():
		print ("Bad interface " + dev)
		exit (1)
	pr = pcapy.open_live(dev, 65536, True, 0)
	if pr.datalink() != pcapy.DLT_EN10MB:
		print ("Interface not Ethernet " + dev)

def compress():
	global GZ
	GZ = []
	GZ.append(str(dump_file))
	GZ.append('.gz')
	GZ = ''.join(GZ)
	infile = open(dump_file, 'rb')
	outfile = gzip.open(GZ, 'wb')
	outfile.writelines(infile)
	outfile.close()
	infile.close()

##############################
############ Main ############
##############################

decoder = EthDecoder()
check()
pcap = pcapy.open_live(dev, max_bytes, promiscuous, read_timeout)
#pcap.setfilter('tcp')
dumper = pcap.dump_open(dump_file)
pcap.loop(packet_limit, write_packet)
sleep(5)
pcap = pcapy.open_offline(dump_file)
pcap.loop(packet_limit, read_packet)
print (list(set([line.strip() for line in open(tmp_file, 'r')])))
  
##############################
############ END #############
##############################
