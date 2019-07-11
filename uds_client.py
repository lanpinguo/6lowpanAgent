# -*- coding: utf-8 -*-

import socket
import sys
import os
 
# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
 
# Connect the socket to the port where the server is listening
server_address = './uds_socket'
client_address = './uds_client'

# Make sure the socket does not already exist
try:
    os.unlink(client_address)
except OSError:
    if os.path.exists(client_address):
        raise

print( 'connecting to %s' % server_address)
try:
    sock.bind(client_address)
except (socket.error) as msg:
    print(msg)
    sys.exit(1)
try:
    
    # Send data
    message = b'This is the message.  It will be repeated.'
    print(  message)
    sock.sendto(message,server_address)
 
    amount_received = 0
    amount_expected = len(message)
    
    while amount_received < amount_expected:
        data = sock.recv(4096)
        amount_received += len(data)
        print( 'received "%s"' % data)
 
finally:
    print( 'closing socket')
    sock.close()
