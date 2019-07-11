# -*- coding: utf-8 -*-
from socket import *

ETH_P_ALL = 0x03

test_pkt_str = """\
00 00 00 00 00 31 32 33 34 35 00 10 6c 3e 41 d8 \
ca 34 12 ff ff f1 fd 05 10 00 4b 12 00 41 60 00 \
00 00 00 06 3a 40 fe 80 00 00 00 00 00 00 02 12 \
4b 00 10 05 fd f1 ff 02 00 00 00 00 00 00 00 00 \
00 00 00 00 00 1a 9b 00 0c 18 47 72 \
"""

test_pkt = bytes.fromhex(test_pkt_str)



rawCliSock =socket(PF_PACKET, SOCK_RAW, 0)
rawCliSock.bind(("veth0",ETH_P_ALL))
while True:
	data = input('>')
	msg = data.encode('utf-8')
	if data == "exit":
		break

	if data == "test":
		rawCliSock.send(test_pkt)
		continue
	# 发送数据:
	rawCliSock.send(msg)
	# 接收数据:
	#print(rawCliSock.recv(BUFSIZ).decode('utf-8'))

rawCliSock.close()

