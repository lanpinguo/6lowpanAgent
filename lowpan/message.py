# -*- coding: utf-8 -*-
"""
Created on Tue Jun 25 20:04:03 2019

@author: lanpinguo
"""

import struct
import lowpan
import lowpan.generic_util


IPv6_IPH_LEN = 40
IPv6_IPADDR_LEN = 16

def chksum(sum, data, length):

    for i in range(0,length,2):   #At least two more bytes
        t = (data[i] << 8) + data[i + 1]
        sum += t
        sum = (sum >> 16) + (sum & 0xFFFF)

    if(length % 2):
        t = (data[length - 1] << 8) + 0
        sum += t
        sum = (sum >> 16) + (sum & 0xFFFF)

    #Return sum in host byte order.
    return (sum & 0xFFFF)


def icmp6chksum(data,length = 0):
    payload_len = (data[4] << 8) + data[5]

    #upper-layer protocol  58 for ICMPv6
    next_header = 58

    #Pseudo ip header
    sum = payload_len + next_header

    #IPv6 src-addr offset 8 from IP layer, src + dst address len is 16*2
    sum = chksum(sum,data[8: 8+32],32)

    sum = chksum(sum,data[IPv6_IPH_LEN:],payload_len)

    return(sum & 0xFFFF)

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
                q.text("xid = ")
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
                q.text("type = ")
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

    def __init__(self,protocol=None,src_addr = None, dst_addr = None):
        self.subclass = None
        self.ver = 0
        self.tos = 0
        self.total_len = 0
        self.identification = 0
        self.frag_Offset = 0
        self.ttl = 255
        self.protocol = protocol
        self.hdr_checksum = 0
        self.src_addr = src_addr
        self.dst_addr = dst_addr

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = IPv4()
        obj.ver = reader.read("!B")[0]
        obj.tos = reader.read("!B")[0]
        obj.total_len = reader.read("!H")[0]
        obj.identification = reader.read("!H")[0]
        obj.frag_Offset = reader.read("!H")[0]
        obj.ttl = reader.read("!B")[0]
        obj.protocol = reader.read("!B")[0]
        obj.hdr_checksum = reader.read("!H")[0]
        obj.src_addr = reader.read("!4s")[0]
        obj.dst_addr = reader.read("!4s")[0]
        subtype = obj.protocol
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


#Internet Protocol version 6 (IPv6)
class IPv6():
    subtypes = {}

    version = 6

    def __init__(self,protocol=None,src_addr = None, dst_addr = None):
        self.subclass = None
        self.ver = 0
        self.tc = 0
        self.flow_label = 0
        self.payload_len = 0
        self.next_hdr = 0
        self.hop = 255
        self.src_addr = src_addr
        self.dst_addr = dst_addr

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = IPv6()
        ver_tc_flow_label = reader.read("!L")[0]
        obj.ver = (ver_tc_flow_label >> 28) & 0xF
        obj.tc = (ver_tc_flow_label >> 20) & 0xFF
        obj.flow_label = (ver_tc_flow_label) & 0xFFFFF
        obj.payload_len = reader.read("!H")[0]
        obj.next_hdr = reader.read("!B")[0]
        obj.hop = reader.read("!B")[0]
        obj.src_addr = reader.read("!16s")[0]
        obj.dst_addr = reader.read("!16s")[0]
        subtype = obj.next_hdr
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

L2.subtypes[0x86dd] = IPv6

class UDP():
    subtypes = {}

    version = 4

    def __init__(self,src_port=0,dst_port = 0):
        self.subclass = None
        self.src_port = src_port
        self.dst_port = dst_port
        self.len = 0
        self.checksum = 0


    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = UDP()
        obj.src_port = reader.read("!H")[0]
        obj.dst_port = reader.read("!H")[0]
        obj.len = reader.read("!H")[0]
        obj.checksum = reader.read("!H")[0]
        subtype = obj.dst_port
        obj.subclass = UDP.subtypes.get(subtype)
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

IPv4.subtypes[0x11] = UDP


class TCP():
    subtypes = {}

    version = 4

    def __init__(self,src_port = 0,dst_port = 0):
        self.subclass = None

        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num  = 0
        self.offset_res = 0
        self.tcp_flag = 0
        self.window  = 0
        self.checksum = 0
        self.urgent_pointer = 0

        return

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = TCP()
        obj.src_port = reader.read("!H")[0]
        obj.dst_port  = reader.read("!H")[0]
        obj.seq_num = reader.read("!L")[0]
        obj.ack_num  = reader.read("!L")[0]
        obj.offset_res = reader.read("!B")[0]
        obj.tcp_flag = reader.read("!B")[0]
        obj.window  = reader.read("!H")[0]
        obj.checksum = reader.read("!H")[0]
        obj.urgent_pointer = reader.read("!H")[0]
        subtype = obj.dst_port
        obj.subclass = UDP.subtypes.get(subtype)
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

IPv4.subtypes[0x06] = TCP


class NXP_802_15_4_Sniffer():
    subtypes = {}

    version = 4

    def __init__(self,sniffer_id = 0,channel = 0):
        self.subclass = None

        self.timestamp = 0
        self.sniffer_id = sniffer_id
        self.channel = channel
        self.lqi =0
        self.len = 0
        self.hdr_len = 14
        self.subtype = 0
        return

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = NXP_802_15_4_Sniffer()
        obj.timestamp = reader.read("!5s")[0]
        obj.sniffer_id = reader.read("!6s")[0]
        obj.channel = reader.read("!B")[0]
        obj.lqi = reader.read("!B")[0]
        obj.len = reader.read("!B")[0]
        obj.subtype, = reader.peek('H', 0)
        obj.subclass = NXP_802_15_4_Sniffer.subtypes.get(obj.subtype & 0x7)
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

UDP.subtypes[1024] = NXP_802_15_4_Sniffer

class IEEE_802_15_4_MHR():
    subtypes = {}

    def __init__(self, dst_pan = 0, dst = 0, ext_dst = None):

        self.fcf     = 0
        self.frame_type = 0
        self.sec_en  = 0
        self.pending = 0
        self.ack_req = 0
        self.intra_pan = 0
        self.dst_addr_mode = 0
        self.src_addr_mode = 0
        self.sn      = 0
        self.dst_pan = dst_pan
        self.src_pan = None
        self.ext_dst = ext_dst
        self.dst     = dst
        self.ext_src = None
        self.src     = None
        self.dst_addr_handle = {0:None,2:self.dst_short_set,3:self.dst_long_set}
        self.src_addr_handle = {0:None,2:self.src_short_set,3:self.src_long_set}

        return

    def mhr_len(self):
        #Frame control
        total_len = 2
        #Sequence number
        total_len += 1

        #Destination PAN identifier
        if (self.src_addr_mode != 0) and (self.intra_pan == 0):
            total_len += 2

        #Destination address
        if (self.dst_addr_mode == 2):
            total_len += 2
        elif (self.dst_addr_mode == 3):
            total_len += 8

        #Source address
        if (self.src_addr_mode == 2):
            total_len += 2
        elif (self.src_addr_mode == 3):
            total_len += 8

        #Source PAN identifier
        if self.dst_addr_mode != 0:
            total_len += 2

        return total_len

    def fcf_unpack(self):
        self.frame_type = self.fcf & 0x7
        self.sec_en  = (self.fcf >> 3) & 0x1
        self.pending = (self.fcf >> 4) & 0x1
        self.ack_req = (self.fcf >> 5) & 0x1
        self.intra_pan = (self.fcf >> 6) & 0x1
        self.dst_addr_mode = (self.fcf >> 10) & 0x3
        self.src_addr_mode = (self.fcf >> 14) & 0x3

    def fcf_pack(self):
        self.fcf = self.frame_type  & 0x7
        self.fcf |= ((self.sec_en & 0x1 ) << 3)
        self.fcf |= ((self.pending & 0x1 ) << 4)
        self.fcf |= ((self.ack_req & 0x1 ) << 5)
        self.fcf |= ((self.intra_pan & 0x1 ) << 6)
        self.fcf |= ((self.dst_addr_mode & 0x3 ) << 10)
        self.fcf |= ((self.src_addr_mode & 0x3 ) << 14)


    def dst_addr_set(self,reader):
        handle = self.dst_addr_handle.get(self.dst_addr_mode)
        if handle:
            handle(reader)

    def src_addr_set(self,reader):
        handle = self.src_addr_handle.get(self.src_addr_mode)
        if handle:
            handle(reader)

    def dst_short_set(self,reader):
        self.dst = reader.read("H")[0]

    def dst_long_set(self,reader):
        self.ext_dst = reader.read("Q")[0]

    def src_short_set(self,reader):
        self.src = reader.read("H")[0]

    def src_long_set(self,reader):
        self.ext_src = reader.read("Q")[0]


    def src_pan_set(self,reader):
        if (self.src_addr_mode != 0) and (self.intra_pan == 0):
            self.src_pan = reader.read("H")[0]

    def dst_pan_set(self,reader):
        if self.dst_addr_mode != 0:
            self.dst_pan = reader.read("H")[0]


    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = IEEE_802_15_4_MHR()
        obj.fcf = reader.read("H")[0]
        obj.fcf_unpack()
        obj.sn = reader.read("B")[0]
        obj.dst_pan_set(reader)
        obj.dst_addr_set(reader)
        obj.src_pan_set(reader)
        obj.src_addr_set(reader)
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



class IEEE_802_15_4_DATA():
    subtypes = {}

    version = 4

    def __init__(self,frame_len = 0, mhr = None):
        self.subclass = None

        self.pattern = None
        self.frame_len = frame_len
        self.mhr_len = 0
        self.mhr = mhr
        self.payload = None
        self.mfr = 0
        return

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = IEEE_802_15_4_DATA()
        obj.mhr = IEEE_802_15_4_MHR.unpack(reader)
        obj.mhr_len = obj.mhr.mhr_len()
        #obj.payload = reader.read("!")
        obj.pattern = reader.peek("!B")[0]
        obj.mfr = reader.read("!H")[0]
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

NXP_802_15_4_Sniffer.subtypes[1] = IEEE_802_15_4_DATA
IEEE_802_15_4_DATA.subtypes[0x41] = IPv6

class ICMPv6():
    subtypes = {}

    version = 6

    def __init__(self,protocol=None,src_addr = None, dst_addr = None):
        self.subclass = None
        self.ver = 0
        self.tc = 0
        self.flow_label = 0
        self.payload_len = 0
        self.next_hdr = 0
        self.hop = 255
        self.src_addr = src_addr
        self.dst_addr = dst_addr

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = IPv6()
        obj.ver = reader.read("!B")[0]
        obj.tos = reader.read("!B")[0]
        obj.total_len = reader.read("!H")[0]
        obj.identification = reader.read("!H")[0]
        obj.frag_Offset = reader.read("!H")[0]
        obj.ttl = reader.read("!B")[0]
        obj.protocol = reader.read("!B")[0]
        obj.hdr_checksum = reader.read("!H")[0]
        obj.src_addr = reader.read("!4s")[0]
        obj.dst_addr = reader.read("!4s")[0]
        subtype = obj.protocol
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

L2.subtypes[0x86dd] = IPv6

class LoWPANv6():
    subtypes = {}

    version = 6

    def __init__(self,pattern = 0, mhr = None):
        self.subclass = None

        self.pattern = pattern
        self.mhr = mhr
        self.payload = None
        self.mfr = 0
        return

    def pack(self):
        packed = []

        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = LoWPANv6()
        obj.pattern = reader.read("!B")[0]
        #obj.payload = reader.read("!")
        obj.mfr = reader.read("!H")[0]
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

IEEE_802_15_4_DATA.subtypes[0x41] = LoWPANv6

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
        raise lowpan.ProtocolError("too short to be an 802.15.4 packet")
    l_sniffer = NXP_802_15_4_Sniffer.unpack(lowpan.generic_util.BufReader(buf))
    return l_sniffer.hdr_len,l_sniffer.len, l_sniffer.subtype, l_sniffer


def parse_802_15_4_header(buf):
    if len(buf) < 8:
        raise lowpan.ProtocolError("too short to be an 802.15.4 packet")
    data = IEEE_802_15_4_DATA.unpack(lowpan.generic_util.BufReader(buf))
    return data.mhr_len,(len(buf) - 2),data.pattern


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
