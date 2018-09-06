#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import pcapy
import getopt
import ConfigParser
from time import strftime
from impacket.ImpactPacket import IP
from impacket.ImpactDecoder import EthDecoder

##############################
########## Variable ##########
##############################

config = ConfigParser.ConfigParser()
config.read("dump.cfg")
dev = config.get("Variable", "dev")
dump_file = strftime("%Y-%m-%d-%H.pcap")
input_file = config.get("Variable", "input_file")
white_file = config.get("Variable", "white_file")
black_file = config.get("Variable", "black_file")
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
	dumper.dump(hdr, data)

def read_packet(hdr, data):
	ether = decoder.decode(data)
	if ether.get_ether_type() == IP.ethertype:
  		iphdr = ether.child()
  		DES = iphdr.get_ip_dst()
  		SRC = iphdr.get_ip_src()
		file = open(tmp_file,"a+")
		file.write(DES, "\n")
                file.write(SRC, "\n")
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

##############################
############ Main ############
##############################

decoder = EthDecoder()

check()
pcap = pcapy.open_live(dev, max_bytes, promiscuous, read_timeout)
dumper = pcap.dump_open(dump_file)
pcap.loop(packet_limit, write_packet)

pcap = pcapy.open_offline(dump_file)
pcap.loop(packet_limit, read_packet)
all_list = list(set([line.strip() for line in open(tmp_file, 'r')]))
file = open(black_file,"a+")
for ip in all_list:
  if ip not in white_list:
    print ("%s is not in %s" % (ip, white_file))
    file.write(ip); file.write("\n")
file.close()
