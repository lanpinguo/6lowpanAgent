#!/usr/bin/env python
#
# Create veth pairs
#

import os
import time
from subprocess import Popen,PIPE,call,check_call
from optparse import OptionParser

parser = OptionParser(version="%prog 0.1")
parser.set_defaults(port_count=1)
parser.add_option("-n", "--port_count", type="int",
                  help="Number of veth pairs to create")
parser.add_option("-N", "--no_wait", action="store_true",
                  help="Do not wait 2 seconds to start daemons")
(options, args) = parser.parse_args()

call(["/sbin/modprobe", "veth"])
for idx in range(0, options.port_count):
    print("Creating veth pair " + str(idx))
    veth = "veth%d" % (idx*2)
    veth_peer = "veth%d" % (idx*2+1)
    call(["/sbin/ip", "link", "add", "name", veth, "type", "veth",
          "peer", "name", veth_peer])

for idx in range(0, 2 * options.port_count):
    cmd = ["/sbin/ifconfig", 
           "veth" + str(idx), 
           "192.168.1" + str(idx) + ".1", 
           "netmask", 
           "255.255.255.0"]
    print("Cmd: " + str(cmd))
    call(cmd)

veths = "veth0"
for idx in range(1, options.port_count):
    veths += ",veth" + str(2 * idx)

    print(veths)

#sys.exit(0)









