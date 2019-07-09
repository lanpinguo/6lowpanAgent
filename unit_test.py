
import time
import os
import sys
import optparse
import lowpan.message as message
from lowpan.tunnel import VirtualTunnel
from lowpan.bridge import Bridge
import logging
import lowpan
from lowpan import config

##@var DEBUG_LEVELS
# Map from strings to debugging levels
DEBUG_LEVELS = {
    'debug'              : logging.DEBUG,
    'verbose'            : logging.DEBUG,
    'info'               : logging.INFO,
    'warning'            : logging.WARNING,
    'warn'               : logging.WARNING,
    'error'              : logging.ERROR,
    'critical'           : logging.CRITICAL
}

CONFIG_DEFAULT = {
    # Logging options
    "log_file"           : "lowpanAgent.log",
    "log_dir"            : None,
    "debug"              : "verbose",

    # Other configuration
    "port_map"           : {},
}

def config_setup():
    """
    Set up the configuration including parsing the arguments

    @return A pair (config, args) where config is an config
    object and args is any additional arguments from the command line
    """

    usage = "usage: %prog [options] (test|group)..."

    description = """\
The default configuration assumes that an OpenFlow 1.0 switch is attempting to
connect to a controller on the machine running OFTest, port 6653. Additionally,
the interfaces veth1, veth3, veth5, and veth7 should be connected to the switch's
dataplane.

"""

    parser = optparse.OptionParser(version="%prog 0.1",
                                   usage=usage,
                                   description=description)

    # Set up default values
    parser.set_defaults(**CONFIG_DEFAULT)


    group = optparse.OptionGroup(parser, "Agent connection options")
    group.add_option("-H", "--host", dest="controller_host",
                      help="IP address to listen on (default %default)")
    group.add_option("-p", "--port", dest="controller_port",
                      type="int", help="Port number to listen on (default %default)")
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Logging options")
    group.add_option("--log-file", help="Name of log file (default %default)")
    group.add_option("--log-dir", help="Name of log directory")
    dbg_lvl_names = sorted(DEBUG_LEVELS.keys(), key=lambda x: DEBUG_LEVELS[x])
    group.add_option("--debug", choices=dbg_lvl_names,
                      help="Debug lvl: debug, info, warning, error, critical (default %default)")
    group.add_option("-v", "--verbose", action="store_const", dest="debug",
                     const="verbose", help="Shortcut for --debug=verbose")
    group.add_option("-q", "--quiet", action="store_const", dest="debug",
                     const="warning", help="Shortcut for --debug=warning")

    parser.add_option_group(group)

    # Might need this if other parsers want command line
    # parser.allow_interspersed_args = False
    (options, args) = parser.parse_args()


    # Convert options from a Namespace to a plain dictionary
    config = CONFIG_DEFAULT.copy()
    for key in config.keys():
        config[key] = getattr(options, key)

    return (config, args)



def logging_setup(config):
    """
    Set up logging based on config
    """

    logging.getLogger().setLevel(DEBUG_LEVELS[config["debug"]])

    if config["log_dir"] != None:
        if os.path.exists(config["log_dir"]):
            import shutil
            shutil.rmtree(config["log_dir"])
        os.makedirs(config["log_dir"])
    else:
        if os.path.exists(config["log_file"]):
            os.remove(config["log_file"])

    lowpan.open_logfile('main')


if __name__ == '__main__':
    import lowpan.selftest as selftest
    buf = selftest.test_pkt
    raw_pkt = message.parse_pkt(buf)
    #print(type(raw_pkt))
    #print(raw_pkt)
    #print(raw_pkt.layers)

    # Setup global configuration
    (new_config, args) = config_setup()
    lowpan.config.update(new_config)

    logging_setup(config)


    vt = VirtualTunnel()
    vt.start()

    bg = Bridge(down_in = vt.poll, down_out = vt.message_send)
    bg.start()

    while True:
        data = input('>')
        if data == 'exit':
            break
    print(data)
    bg.kill()
    vt.kill()

