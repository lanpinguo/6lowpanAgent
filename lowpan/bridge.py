# -*- coding: utf-8 -*-


import sys
import os
import socket
import time
import struct
import select
import logging
from threading import Thread
from threading import Lock
from threading import Condition
from lowpan import generic_util
import lowpan

ETH_P_ALL = 0x03
RCV_SIZE_DEFAULT = 32768


##@todo Find a better home for these identifiers (controller)
RCV_SIZE_DEFAULT = 32768
LISTEN_QUEUE_SIZE = 1

class Bridge(Thread):
    """
    Class abstracting the bridge interface to the agent.
    """

    def __init__(self, veth = 'veth0', tun_unix_addr = None,bdg_unix_addr = 'uds_bridge'):
        Thread.__init__(self)

        self.rcv_size = RCV_SIZE_DEFAULT

        self.tx_lock = Lock()

        # Used to wake up the event loop from another thread
        self.waker = generic_util.EventDescriptor()

        # Counters
        self.socket_errors = 0
        self.parse_errors = 0
        self.packets_total = 0
        self.packets_expired = 0
        self.packets_handled = 0
        self.poll_discards = 0

        # State
        self.sync = Lock()
        self.handlers = {}
        self.keep_alive = False
        self.active = True

        # message/packet queue
        # Protected by the packets_cv lock / condition variable
        self.packets = []
        self.packets_cv = Condition()
        self.packet_in_count = 0

        # Settings
        self.tun_unix_addr = tun_unix_addr
        self.bdg_unix_addr = bdg_unix_addr
        self.dbg_state = "init"
        self.logger = logging.getLogger("Bridge")
        self.filter_packet_in = False # Drop "excessive" packet ins
        self.pkt_in_run = 0 # Count on run of packet ins
        self.pkt_in_filter_limit = 50 # Count on run of packet ins
        self.pkt_in_dropped = 0 # Total dropped packet ins
        self.transact_to = 15 # Transact timeout default value; add to config



        self.debug = False

        # Create socket
        self.veth = veth
        self.logger.info("Create  at " + str(self.veth))
        self.veth_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 0)
        self.veth_socket.bind((self.veth,ETH_P_ALL))

        # Make sure the socket does not already exist
        try:
            os.unlink(self.bdg_unix_addr)
        except OSError:
            if os.path.exists(self.bdg_unix_addr):
                raise
        self.tunnel_socket = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        # Bind the socket to the port
        self.logger.info("Create/listen at " + str(self.bdg_unix_addr))
        self.tunnel_socket.bind(self.bdg_unix_addr)

    def filter_packet(self, rawmsg, hdr):
        """
        Check if packet should be filtered

        Currently filters packet in messages
        @return Boolean, True if packet should be dropped
        """
        # XXX didn't actually check for packet-in...
        return False
        # Add check for packet in and rate limit
        if self.filter_packet_in:
            # If we were dropping packets, report number dropped
            # TODO dont drop expected packet ins
            if self.pkt_in_run > self.pkt_in_filter_limit:
                self.logger.debug("Dropped %d packet ins (%d total)"
                            % ((self.pkt_in_run -
                                self.pkt_in_filter_limit),
                                self.pkt_in_dropped))
            self.pkt_in_run = 0

        return False

    def _pkt_handle(self,pkt):
        print(pkt[1])
        print(generic_util.hex_dump_buffer(pkt[0]))



    def wakeup(self):
        """
        Wake up the event loop, presumably from another thread.
        """
        self.waker.notify()

    def sockets(self):
        """
        Return list of sockets to select on.
        """
        socs = [self.veth_socket, self.tunnel_socket]
        return [x for x in socs if x]

    def _socket_ready_handle(self, s):
        """
        Handle an input-ready socket

        @param s The socket object that is ready
        @returns 0 on success, -1 on error
        """

        if s and s == self.tunnel_socket:
            try:
                pkt = self.tunnel_socket.recvfrom(self.rcv_size)
            except:
                self.logger.warning("Error on switch read")
                return -1

            self._pkt_handle(pkt)

        elif s and s == self.veth_socket:
            try:
                pkt = self.veth_socket.recv(self.rcv_size)
            except:
                self.logger.warning("Error on switch read")
                return -1

            if not self.active:
                return 0

            if len(pkt) == 0: # Still no packet
                self.logger.warning("Zero-length switch read; closing cxn")
                self.logger.info(str(self))
                return -1
        else:
            self.logger.error("Unknown socket ready: " + str(s))
            return -1

        return 0


    def run(self):
        """
        Activity function for class

        Assumes connection to switch already exists.  Listens on
        switch_socket for messages until an error (or zero len pkt)
        occurs.

        When there is a message on the socket, check for handlers; queue the
        packet if no one handles the packet.

        See note for controller describing the limitation of a single
        connection for now.
        """

        self.dbg_state = "running"

        while self.active:
            try:
                sel_in, sel_out, sel_err = \
                    select.select(self.sockets(), [], self.sockets(), 1)
            except:
                print( sys.exc_info())
                self.logger.error("Select error, disconnecting")
                self.disconnect()

            for s in sel_err:
                self.logger.error("Got socket error on: " + str(s) + ", disconnecting")
                self.disconnect()

            for s in sel_in:
                if self._socket_ready_handle(s) == -1:
                    self.disconnect()


        # End of main loop
        self.dbg_state = "closing"
        self.logger.info("Exiting bridge thread")
        self.shutdown()




    def kill(self):
        """
        Force the controller thread to quit
        """
        self.active = False
        self.wakeup()
        self.join()

    def shutdown(self):
        """
        Shutdown the controller closing all sockets

        @todo Might want to synchronize shutdown with self.sync...
        """

        self.active = False

        self.wakeup()
        self.dbg_state = "down"

    def register(self, msg_type, handler):
        """
        Register a callback to receive a specific message type.

        Only one handler may be registered for a given message type.

        WARNING:  A lock is held during the handler call back, so
        the handler should not make any blocking calls

        @param msg_type The type of message to receive.  May be DEFAULT
        for all non-handled packets.  The special type, the string "all"
        will send all packets to the handler.
        @param handler The function to call when a message of the given
        type is received.
        """
        # Should check type is valid
        if not handler and msg_type in self.handlers.keys():
            del self.handlers[msg_type]
            return
        self.handlers[msg_type] = handler

    def poll(self, exp_msg=None, timeout=-1):
        """
        Wait for the next OF message received from the switch.

        @param exp_msg If set, return only when this type of message
        is received (unless timeout occurs).

        @param timeout Maximum number of seconds to wait for the message.
        Pass -1 for the default timeout.

        @retval A pair (msg, pkt) where msg is a message object and pkt
        the string representing the packet as received from the socket.
        This allows additional parsing by the receiver if necessary.

        The data members in the message are in host endian order.
        If an error occurs, (None, None) is returned
        """

        if exp_msg is None:
            self.logger.warn("DEPRECATED polling for any message class")
            klass = None
        else:
            raise ValueError("Unexpected exp_msg argument %r" % exp_msg)


        # Take the packet from the queue
        def grab():
            for i, (msg, pkt) in enumerate(self.packets):
                if klass is None or isinstance(msg, klass):
                    self.logger.debug("Got %s message", msg.__class__.__name__)
                    return self.packets.pop(i)
            # Not found
            return None

        with self.packets_cv:
            ret = generic_util.timed_wait(self.packets_cv, grab, timeout=timeout)

        if ret != None:
            (msg, pkt) = ret
            return (msg, pkt)
        else:
            return (None, None)

    def transact(self, msg, timeout=-1):
        """
        Run a message transaction with the switch

        Send the message in msg and wait for a reply with a matching
        transaction id.  Transactions have the highest priority in
        received message handling.

        @param msg The message object to send; must not be a string
        @param timeout The timeout in seconds; if -1 use default.
        """


        self.logger.debug("Running transaction %d" % msg.xid)

        with self.xid_cv:
            if self.xid:
                self.logger.error("Can only run one transaction at a time")
                return (None, None)

            self.xid = msg.xid
            self.xid_response = None
            self.message_send(msg)

            self.logger.debug("Waiting for transaction %d" % msg.xid)
            generic_util.timed_wait(self.xid_cv, lambda: self.xid_response, timeout=timeout)

            if self.xid_response:
                (resp, pkt) = self.xid_response
                self.xid_response = None
            else:
                (resp, pkt) = (None, None)

        if resp is None:
            self.logger.warning("No response for xid " + str(self.xid))
        return (resp, pkt)

    def message_send(self, msg):
        """
        Send the message to the switch

        @param msg A string or OpenFlow message object to be forwarded to
        the switch.
        """

        if not self.switch_socket:
            # Sending a string indicates the message is ready to go
            raise Exception("no socket")


        outpkt = msg.pack()

        self.logger.debug("Msg out: version %d class %s len %d xid %d",
                          msg.version, type(msg).__name__, len(outpkt), msg.xid)

        with self.tx_lock:
            if self.switch_socket.sendall(outpkt) is not None:
                raise AssertionError("failed to send message to switch")

        return 0 # for backwards compatibility

    def clear_queue(self):
        """
        Clear the input queue and report the number of messages
        that were in it
        """
        enqueued_pkt_count = len(self.packets)
        with self.packets_cv:
            self.packets = []
        return enqueued_pkt_count

    def __str__(self):
        string = "Controller:\n"
        string += "  state           " + self.dbg_state + "\n"
        string += "  switch_addr     " + str(self.switch_addr) + "\n"
        string += "  pending pkts    " + str(len(self.packets)) + "\n"
        string += "  total pkts      " + str(self.packets_total) + "\n"
        string += "  expired pkts    " + str(self.packets_expired) + "\n"
        string += "  handled pkts    " + str(self.packets_handled) + "\n"
        string += "  poll discards   " + str(self.poll_discards) + "\n"
        string += "  parse errors    " + str(self.parse_errors) + "\n"
        string += "  sock errrors    " + str(self.socket_errors) + "\n"
        string += "  max pkts        " + str(self.max_pkts) + "\n"
        string += "  target switch   " + str(self.switch) + "\n"
        string += "  host            " + str(self.host) + "\n"
        string += "  port            " + str(self.port) + "\n"
        string += "  keep_alive      " + str(self.keep_alive) + "\n"
        string += "  pkt_in_run      " + str(self.pkt_in_run) + "\n"
        string += "  pkt_in_dropped  " + str(self.pkt_in_dropped) + "\n"
        return string

    def show(self):
        print(str(self))



