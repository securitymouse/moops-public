import time
import random
import socket
from threading import Thread


class Fling(dict, Thread):
    __IN__ = "in"
    __OUT__ = "out"
    __NAME__ = "name"
    __MATCH__ = "match"
    __MANGLE__ = "mangle"
    __THREADID__ = "threadID"
    __THREADNAME__ = "threadname"

    __KEYS__ = [
        __IN__,
        __OUT__,
        __NAME__,
        __MATCH__,
        __THREADID__,
        __THREADNAME__
        ]

    _in = None
    _out = None
    itemlist = None
    do_exit = False

    def __init__(self, *args, **kw):
        dict.__init__(self, *args, **kw)
        Thread.__init__(self)

        if self.itemlist and self.__THREADID__ in self.itemlist:
            self.threadID = self[self.__THREADID__]
        if self.itemlist and self.__THREADNAME__ in self.itemlist:
            self.name = self[self.__THREADNAME__]

        self.itemlist = super(Fling, self).keys()
        self.bootstrap()

    def __hash__(self):
        return hash(tuple(sorted(self.items())))

    def bootstrap(self):
        if ((self.__IN__ not in self.itemlist) or
                (self.__OUT__ not in self.itemlist)):
                return

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        s.bind((self[self.__IN__], 0))
        self._in = s

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        r = s.bind((self[self.__OUT__], 0))
        self._out = s

    def run(self):
        while True:
            if self.do_exit:
                break

            if not self._in or not self._out:
                print("No interfaces, yet.")
                time.sleep(3)
                continue

            x = self._in.recvfrom(65536)
            if self.__MATCH__ in self.itemlist:
                if not self[self.__MATCH__] == x[0]:
                    continue

                if self.__MANGLE__ not in self.itemlist:
                    print("Fling: nothing to mangle")
                    continue

                # Mangle and update the packet
                x = self[self.__MANGLE__](x[0])
                self._out.send(x)

    def join(self):
        self.do_exit = True
