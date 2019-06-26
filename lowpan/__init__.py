# -*- coding: utf-8 -*-


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

