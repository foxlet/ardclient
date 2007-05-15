# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

import popen2
import struct
import sys


def hexdump(data):
    ''' Hexdump data.
    '''
    (fout, fin) = popen2.popen2("/usr/bin/hexdump -Cv")
    fin.write(data)
    fin.close()
    return fout.read()

def dump(filename, data):
    f = open(filename, "w")
    f.write(data)
    f.close


MSG_INFO="Info"
MSG_ERROR="Error"
MSG_WARN="Warning"
def log(type, text, verbose=False):
    ''' Print message to stderr.
    '''
    if verbose or type == MSG_ERROR:
        msg = "[%s] %s\n" % (type, text)
        sys.stderr.write(msg)


def contents(filename):
    ''' Read contents of a file and return them.
    '''
    fd = open(filename, "r")
    try:
        return fd.read()
    finally:
        fd.close()
