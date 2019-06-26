# -*- coding: utf-8 -*-
"""
Created on Tue Jun 25 20:04:03 2019

@author: lanpinguo
"""

import struct
import lowpan
import lowpan.generic_util


class message(lowpan.LPObject):
	subtypes = {}

	version = 4

	def __init__(self, type=None, xid=None):
		if type != None:
			self.type = type
		else:
			self.type = 0
		if xid != None:
			self.xid = xid
		else:
			self.xid = None
		return

	def pack(self):
		packed = []
		packed.append(struct.pack("!B", self.version))
		packed.append(struct.pack("!B", self.type))
		packed.append(struct.pack("!H", 0)) # placeholder for length at index 2
		packed.append(struct.pack("!L", self.xid))
		length = sum([len(x) for x in packed])
		packed[2] = struct.pack("!H", length)
		return ''.join(packed)

	@staticmethod
	def unpack(reader):
		subtype, = reader.peek('B', 1)
		subclass = message.subtypes.get(subtype)
		if subclass:
			return subclass.unpack(reader)

		obj = message()
		_version = reader.read("!B")[0]
		#assert(_version == 4)
		obj.type = reader.read("!B")[0]
		_length = reader.read("!H")[0]
		orig_reader = reader
		reader = orig_reader.slice(_length, 4)
		obj.xid = reader.read("!L")[0]
		return obj

	def __eq__(self, other):
		if type(self) != type(other): return False
		if self.type != other.type: return False
		if self.xid != other.xid: return False
		return True

	def pretty_print(self, q):
		q.text("message {")
		with q.group():
			with q.indent(2):
				q.breakable()
				q.text("xid = ");
				if self.xid != None:
					q.text("%#x" % self.xid)
				else:
					q.text('None')
			q.breakable()
		q.text('}')

class VLAN():

	def __init__(self, vid = 0, type = 0x8100):

		self.type = 0x8100
		self.vid = vid

	def pack(self):
		packed = []
		packed.append(struct.pack("!H", self.type))
		packed.append(struct.pack("!H", self.vid))
		return ''.join(packed)

	@staticmethod
	def unpack(reader):
		obj = VLAN()
		obj.type = reader.read("!H")[0]
		obj.vid = reader.read("!H")[0]
		return obj

	def __eq__(self, other):
		if type(self) != type(other): return False
		if self.type != other.type: return False
		if self.vid != other.vid: return False
		return True

	def pretty_print(self, q):
		q.text("VLAN {")
		with q.group():
			with q.indent(2):
				q.breakable()
				q.text("type = ");
				if self.xid != None:
					q.text("%#x" % self.type)
				else:
					q.text('None')
			q.breakable()
		q.text('}')



class L2():
	subtypes = {}

	def __init__(self, da = None, sa = None, vlans = [], type=0x0800):
		self.type = type
		self.da = da
		self.sa = sa
		self.vlans = vlans
		self.subclass = None
		return


	def pack(self):
		packed = []
		packed.append(struct.pack("!6s", self.da))
		packed.append(struct.pack("!6s", self.sa))
		for vlan in self.vlans:
			packed.append(vlan.pack())
		packed.append(struct.pack("!H", self.type))
		return ''.join(packed)

	@staticmethod
	def unpack(reader):
		obj = L2()
		obj.da = reader.read("!6s")[0]
		obj.sa = reader.read("!6s")[0]
		for i in range(4):
			subtype, = reader.peek('H', 0)
			if subtype == 0x8100:
				obj.vlans.append(VLAN.unpack(reader))
			else:
				break
		obj.type = reader.read("!H")[0]
		obj.subclass = L2.subtypes.get(obj.type)
		return obj

	def __eq__(self, other):
		if type(self) != type(other): return False
		if self.da != other.da: return False
		if self.sa != other.sa: return False
		if self.vlans != other.vlans: return False
		return True

	def pretty_print(self, q):
		q.text("L2 {")
		with q.group():
			with q.indent(2):
				pass
			q.breakable()
		q.text('}')

class IPv4():
	subtypes = {}

	version = 4

	def __init__(self):
		self.subclass = None

	def pack(self):
		packed = []

		return ''.join(packed)

	@staticmethod
	def unpack(reader):
		obj = IPv4()
		subtype = 0
		obj.subclass = IPv4.subtypes.get(subtype)
		return obj

	def __eq__(self, other):
		if type(self) != type(other): return False
		return True

	def pretty_print(self, q):
		q.text("packet {")
		with q.group():
			with q.indent(2):
				pass
			q.breakable()
		q.text('}')

L2.subtypes[0x0800] = IPv4

class PACKET(lowpan.LPObject):
	subtypes = {}

	version = 4

	def __init__(self,layers = []):
		self.layers = layers
		return

	def pack(self):
		packed = []
		for l in self.layers:
			packed.append(l.pack())
		return ''.join(packed)

	@staticmethod
	def unpack(reader):
		obj = PACKET()
		curLayer = L2.unpack(reader)
		obj.layers.append(curLayer)
		nextLayer = curLayer.subclass
		while nextLayer:
			curLayer = nextLayer.unpack(reader)
			obj.layers.append(curLayer)
			nextLayer = curLayer.subclass

		return obj

	def __eq__(self, other):
		if type(self) != type(other): return False
		if self.layers != other.layers: return False
		return True

	def pretty_print(self, q):
		q.text("packet {")
		with q.group():
			with q.indent(2):
				pass
			q.breakable()
		q.text('}')


def parse_header(buf):
	if len(buf) < 8:
		raise lowpan.ProtocolError("too short to be an l2 ethernet packet")
	return struct.unpack("!6s6sH",buf[0:14])

def parse_message(buf):
	da, sa, eth_type = parse_header(buf)
	return message.unpack(lowpan.generic_util.BufReader(buf))

def parse_pkt(buf):
	if len(buf) < 64:
		raise lowpan.ProtocolError("too short to be an l2 ethernet packet")
	return PACKET.unpack(lowpan.generic_util.BufReader(buf))

if __name__ == '__main__':
	import lowpan.selftest as selftest
	buf = selftest.test_pkt
	raw_pkt = parse_pkt(buf)
	print(type(raw_pkt))
	print(raw_pkt)
	print(raw_pkt.layers)
