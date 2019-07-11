# -*- coding: utf-8 -*-

import socket
import sys
import os
 
server_address = './uds_socket'
 
# Make sure the socket does not already exist
try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise
# Create a UDS socket
sock = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
# Bind the socket to the port
print(  'starting up on %s' % server_address)
sock.bind(server_address)
 
 
while True:
    # Wait for a connection
    try:
        connection = sock
 
        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(4096)
            print(data)
            
    finally:
        # Clean up the connection
        connection.close()
