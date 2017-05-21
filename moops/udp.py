import socket


class UDP(dict):
    # Our dictionary, so it's easy to access
    __SRC__ = "src"
    __DST__ = "dst"
    __LENGTH__ = "length"
    __CHECKSUM__ = "checksum"
    __NEXT__ = "next"
    __NAME__ = "name"
    __PREV__ = "prev"

    # Not "exported"; internal use only
    __BYTES__ = "bytes"
    __INT_PTR__ = "__ptr"
    __NEXTDATA__ = "__next"

    __KEYS__ = [
        __LENGTH__,
        __CHECKSUM__,
        __SRC__,
        __DST__,
        __NEXT__,
        __PREV__,
        __NAME__
        ]

    __SKIP__ = [
        __NEXT__,
        __NAME__,
        __PREV__,
        __BYTES__,
        __NEXTDATA__
        ]

    itemlist = None
    inbount = False

    def __init__(self, *args, **kw):
        dict.__init__(self, *args, **kw)
        self.itemlist = super(UDP, self).keys()
        self[self.__NAME__] = "UDP"

        if self.__BYTES__ in self.itemlist:
            self.inbound = True
            self.parse()

    def __hash__(self):
        return hash(tuple(sorted(self.items())))

    def __eq__(self, x):
        udp = UDP({self.__BYTES__: x})
        udp.parse()
        for i in self.itemlist:
            if i in self.__SKIP__:
                continue
            if i not in udp or self[i] != udp[i]:
                return False

            if self.__NEXT__ in self.itemlist:
                return self[self.__NEXT__] == udp.next()

        return True

    def __add__(self, x):
        raise Exception("WHAT")

    def __bytes__(self):
        # Now, generate the summable header
        b = b''
        b += self.convert_port(self.__SRC__)
        b += self.convert_port(self.__DST__)
        b += self.convert_length()
        b += self.convert_checksum(b)

        b += self.getnext()

        # Ready!
        self[self.__BYTES__] = b
        return b

    # This represent the keys that alter the behavior of the module
    def moops_keys(self):
        k = self.__KEYS__
        for i in self.keys():
            k += [i]
        return k

    def next(self):
        if self.__NEXTDATA__ not in self.itemlist:
            return b''
        return self[self.__NEXTDATA__] 

    def pad_data(self, n):
        # This must be adjusted when we add app layers
        if self.__NEXTDATA__ in self.itemlist:
            p = self[self.__NEXTDATA__]
            p += bytes(n)
            self[self.__NEXTDATA__] = p

    def setnext(self, x):
        self[self.__NEXT__] = x
        return x

    def getnext(self):
        if self.__NEXT__ not in self.itemlist:
            if self.__NEXTDATA__ in self.itemlist:
                return self[self.__NEXTDATA__]
            return b''
        return bytes(self[self.__NEXT__])

    def convert_port(self, n):
        a = 53
        if n in self.itemlist:
            a = self[n]
        return bytes([(a >> 8) & 0xff, (a & 0xff)])

    def generate_checksum(self, b):
        if self.__PREV__ not in self.itemlist:
            raise Exception("udp.generate_checksum: no prev")

        # Apply the pseudo header
        b = self[self.__PREV__].pseudoheader(len(b)) + b

        s = 0
        i = 0
        c = len(b)
        while c > 1:
            s += int.from_bytes(b[i:i+2], "big")
            i += 2
            c -= 2

        if c > 0:
            s += int.from_bytes(b[i:i+1], "big")

        while (s >> 16) != 0:
            s = (s & 0xffff) + (s >> 16)

        return ~s

    def convert_length(self):
        x = 0
        # Calculate the size of the full packet if the user doesn't want a
        # specific length.
        if self.__LENGTH__ not in self.itemlist or self.inbound:
            h = 8
            d = len(self.next())
            x = h + d
            if (x & 1):
                x += 1
                self.pad_data(1)
        else:
            x = self[self.__LENGTH__]

        return bytes([((x >> 8) & 0xff), (x & 0xff)])

    def convert_checksum(self, b):
        x = 0
        if self.__CHECKSUM__ not in self.itemlist or self.inbound:
            x = self.generate_checksum(b + b'\x00\x00' + self.getnext())
        else:
            x = self[self.__CHECKSUM__]

        return bytes([((x >> 8) & 0xff), (x & 0xff)])

    def parse(self):
        if self.__BYTES__ not in self.itemlist:
            self.__bytes__()

        # While we can theoretically send an invalid or short packet, there is
        # little value in parsing a packet that isn't full (some exceptions)
        if len(self[self.__BYTES__]) < 8:
            raise Exception("Invalid packet length")

        self[self.__INT_PTR__] = 0

        self.parseshort(self.__SRC__)
        self.parseshort(self.__DST__)
        self.parseshort(self.__LENGTH__)
        self.parseshort(self.__CHECKSUM__)
        self.parsenext()

        self.pop(self.__INT_PTR__, None)

    def parsebyte(self, n):
        p = self[self.__INT_PTR__]
        self[n] = self[self.__BYTES__][p]
        self[self.__INT_PTR__] = p + 1

    def parseshort(self, n):
        p = self[self.__INT_PTR__]
        self[n] = (self[self.__BYTES__][p] << 8) | self[self.__BYTES__][p + 1]
        self[self.__INT_PTR__] = p + 2

    def parseint(self, n):
        p = self[self.__INT_PTR__]
        self[n] = ((self[self.__BYTES__][p] << 24) |
                   (self[self.__BYTES__][p + 1] << 16) |
                   (self[self.__BYTES__][p + 2] << 8) |
                   (self[self.__BYTES__][p + 3]))

        self[self.__INT_PTR__] = p + 4

    def parsenext(self):
        p = self[self.__INT_PTR__]
        self[self.__NEXTDATA__] = self[self.__BYTES__][p:]
        self[self.__INT_PTR__] = p + len(self[self.__NEXTDATA__])
