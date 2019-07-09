# -*- coding: utf-8 -*-
import sys
import os
import logging

# Global config dictionary
# Populated by oft.
config = {}



version_names = {
    1: "1.0",
    2: "1.1",
}

def protocol(ver):
    """
    Import and return the protocol module for the given wire version.
    """
    if ver == 1:
        return 1

    if ver == 2:
        return 2


    raise ValueError

class ProtocolError(Exception):
    """
    Raised when failing to deserialize an invalid Lowpan message.
    """
    pass

class Unimplemented(Exception):
    """
    Raised when an Lowpan feature is not yet implemented in PyLoxi.
    """
    pass

def unimplemented(msg):
    raise Unimplemented(msg)

class LPObject(object):
    """
    Superclass of all Lowpan classes
    """
    def __init__(self, *args):
        raise NotImplementedError("cannot instantiate abstract class")

    def __ne__(self, other):
        return not self.__eq__(other)

    def show(self):
        import lowpan.pp
        return lowpan.pp.pp(self)



def open_logfile(name):
    """
    (Re)open logfile

    When using a log directory a new logfile is created for each test. The same
    code is used to implement a single logfile in the absence of --log-dir.
    """

    _format = "%(asctime)s.%(msecs)03d  %(name)-10s: %(levelname)-8s: %(message)s"
    _datefmt = "%H:%M:%S"

    if config["log_dir"] != None:
        filename = os.path.join(config["log_dir"], name) + ".log"
    else:
        filename = config["log_file"]

    logger = logging.getLogger()

    # Remove any existing handlers
    for handler in logger.handlers:
        logger.removeHandler(handler)
        handler.close()

    # Add a new handler
    handler = logging.FileHandler(filename, mode='a')
    handler.setFormatter(logging.Formatter(_format, _datefmt))
    logger.addHandler(handler)
