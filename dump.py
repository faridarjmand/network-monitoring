#!/usr/bin/python
# -*- coding: utf-8 -*-

## Created By.Farid Arjmand ##

import pcapy
import sys
import os
import getopt
import ConfigParser
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP
from time import strftime

##############################
########## Variable ##########
##############################

config = ConfigParser.ConfigParser()
config.read("dump.cfg")
dev = config.get("Variable", "dev")
dump_file = config.get("Variable", "dump_file")
input_file = config.get("Variable", "input_file")
white_file = config.get("Variable", "white_file")
tmp_file = config.get("Variable", "tmp_file")
packet_limit = config.getint("Variable", "packet_limit")
max_bytes = config.getint("Variable", "max_bytes")
promiscuous = config.getboolean("Variable", "promiscuous")
read_timeout = config.getint("Variable", "read_timeout")
white_list = list(set([line.strip() for line in open(white_file, 'r')]))

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
		file = open(tmp_file,"a+")
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
	
def usage():
	print sys.argv[0] + """
	-i <dev>
	-r <input_file>
	-w <output_file>"""
	sys.exit(1)

##############################
############ Main ############
##############################

decoder = EthDecoder()

try:
	cmd_opts = "i:r:w:"
	opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
	usage()

for opt in opts:
	if opt[0] == "-w":
		dump_file = opt[1]
	elif opt[0] == "-i":
		dev = opt[1]
	elif opt[0] == "-r":
		input_file = opt[1]
	else:
		usage()

if input_file == "None":
	check()
	pcap = pcapy.open_live(dev, max_bytes, promiscuous, read_timeout)
	#pcap.setfilter('tcp')
	dumper = pcap.dump_open(dump_file)
	pcap.loop(packet_limit, write_packet)
else:
	pcap = pcapy.open_offline(input_file)
	pcap.loop(packet_limit, read_packet)
	all_list = list(set([line.strip() for line in open(tmp_file, 'r')]))
	for ip in all_list:
		if ip not in white_list:
			print ip
  
##############################
############ END #############
##############################
