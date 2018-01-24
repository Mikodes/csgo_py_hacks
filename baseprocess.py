#!/usr/bin/env python
# -*- coding: UTF8 -*-

""" Base class for process not linked to any platform """

import re
import struct

def re_to_unicode(s):
    newstring = ''
    for c in s:
        newstring += re.escape(c) + '\\x00'

    return newstring


def type_unpack(type):
    """ return the struct and the len of a particular type """
    type = type.lower()
    s = None
    l = None
    if type == 'short':
        s = 'h'
        l = 2
    elif type == 'bool':
        s = 'c'
        l = 1
    elif type == 'ushort':
        s = 'H'
        l = 2
    elif type == 'int':
        s = 'i'
        l = 4
    elif type == 'uint':
        s = 'I'
        l = 4
    elif type == 'long':
        s = 'l'
        l = 4
    elif type == 'ulong':
        s = 'L'
        l = 4
    elif type == 'float':
        s = 'f'
        l = 4
    elif type == 'double':
        s = 'd'
        l = 8
    else:
        raise TypeError('Unknown type %s' % type)
    return ('<' + s, l)


def hex_dump(data, addr = 0, prefix = '', ftype = 'bytes'):
    """
    function originally from pydbg, modified to display other types
    """
    dump = prefix
    slice = ''
    if ftype != 'bytes':
        structtype, structlen = type_unpack(ftype)
        for i in range(0, len(data), structlen):
            if addr % 16 == 0:
                dump += ' '
                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'

                dump += '\n%s%08X: ' % (prefix, addr)
                slice = ''
            tmpval = 'NaN'
            try:
                packedval = data[i:i + structlen]
                tmpval = struct.unpack(structtype, packedval)[0]
            except Exception as e:
                print e

            if tmpval == 'NaN':
                dump += '{:<15} '.format(tmpval)
            elif ftype == 'float':
                dump += '{:<15.4f} '.format(tmpval)
            else:
                dump += '{:<15} '.format(tmpval)
            addr += structlen

    else:
        for byte in data:
            if addr % 16 == 0:
                dump += ' '
                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'

                dump += '\n%s%08X: ' % (prefix, addr)
                slice = ''
            dump += '%02X ' % ord(byte)
            slice += byte
            addr += 1

    remainder = addr % 16
    if remainder != 0:
        dump += '   ' * (16 - remainder) + ' '
    for char in slice:
        if ord(char) >= 32 and ord(char) <= 126:
            dump += char
        else:
            dump += '.'

    return dump + '\n'


class ProcessException(Exception):
    pass

class BaseProcess(object):

    def __init__(self, *args, **kwargs):
        """ Create and Open a process object from its pid or from its name """
        self.h_process = None
        self.pid = None
        self.isProcessOpen = False
        self.buffer = None
        self.bufferlen = 0

    def __del__(self):
        self.close()

    def close(self):
        pass
    def iter_region(self, *args, **kwargs):
        raise NotImplementedError
    def write_bytes(self, address, data):
        raise NotImplementedError

    def read_bytes(self, address, bytes = 4):
        raise NotImplementedError

    def get_symbolic_name(self, address):
        return '0x%08X' % int(address)

    def read(self, address, type = 'uint', maxlen = 50, errors='raise'):
        if type == 's' or type == 'string':
            s = self.read_bytes(int(address), bytes=maxlen)
            news = ''
            for c in s:
                if c == '\x00':
                    return news
                news += c
            if errors=='ignore':
                return news
            raise ProcessException('string > maxlen')
        else:
            if type == 'bytes' or type == 'b':
                return self.read_bytes(int(address), bytes=1)
            s, l = type_unpack(type)
            return struct.unpack(s, self.read_bytes(int(address), bytes=l))[0]

    def write(self, address, data, type = 'uint'):
        if type != 'bytes':
            s, l = type_unpack(type)
            return self.write_bytes(int(address), struct.pack(s, data))
        else:
            return self.write_bytes(int(address), data)