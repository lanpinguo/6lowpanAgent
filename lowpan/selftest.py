# -*- coding: utf-8 -*-
"""
Created on Wed Jun 26 09:48:17 2019

@author: lanpinguo
"""

test_pkt_str = """
14 75 90 73 55 b4 98 54 1b a2 87 d0 08 00 45 00
00 5a 00 00 00 00 ff 11 00 00 c0 a8 02 01 c0 a8
02 64 03 e8 04 00 00 46 00 00 00 00 00 00 00 31
32 33 34 35 00 00 6c 2f 41 d8 a6 34 12 ff ff f1
fd 05 10 00 4b 12 00 41 60 00 00 00 00 06 3a 40
fe 80 00 00 00 00 00 00 02 12 4b 00 10 05 fd f1
ff 02 00 00 00 00 00 00 00 00 00 00 00 00 00 1a
9b 00 0c 18 00 00
"""

test_pkt = bytes.fromhex(test_pkt_str)



if __name__ == '__main__':
	print(type(test_pkt))
	print(test_pkt)