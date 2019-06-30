
# import modules
import socket
#import IN
import struct
import binascii
import os


import lowpan.message

ETH_P_ALL = 0x03

# if operating system is windows
if os.name == "nt":
	s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
	s.bind(("192.168.2.103",0))
	s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
	s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# if operating system is linux
else:
	s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 0)
	#s.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE,b"usb0") #not work
	s.bind(("usb0",ETH_P_ALL))
# create loop
while True:

	# Capture packets from network
	pkt = s.recvfrom(1500)
	print(pkt)
	#if pkt[1][0] == 'usb0':
	#	print(pkt[1])

	# Parse the header to get type
	#hdr_version, hdr_type, hdr_length, hdr_xid = lowpan.message.parse_header(pkt[0])
	#print(hdr_version)



