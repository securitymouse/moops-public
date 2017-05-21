class Ether(dict):
    # Exported types
    __SRC__ = "src"
    __DST__ = "dst"
    __TYPE__ = "type"
    __NEXT__ = "next"
    __NAME__ = "name"

    __KEYS__ = [
        __NAME__,
        __SRC__,
        __DST__,
        __TYPE__,
        __NEXT__
        ]

    # Internal
    __BYTES__ = "bytes"
    __INT_PTR__ = "__ptr"
    __NEXTDATA__ = "__next"

    __SKIP__ = [
        __NAME__,
        __NEXT__,
        __BYTES__,
        __NEXTDATA__
        ]

    __EMPTY__ = bytes(6)

    itemlist = None
    inbound = False

    def __init__(self, *args, **kw):
        dict.__init__(self, *args, **kw)
        self.itemlist = super(Ether, self).keys()
        self[self.__NAME__] = 'Ether'

        if self.__BYTES__ in self.itemlist:
            self.inbound = True
            self.parse()

    def __iter__(self):
        for i in self.__KEYS__:
            if i in self.__SKIP__:
                continue

            if i not in self.itemlist:
                continue

            yield i

    def __hash__(self):
        return hash(tuple(sorted(self.items())))

    def __eq__(self, x):
        e = Ether({self.__BYTES__: x})
        e.parse()
        for i in self.itemlist:
            if i in self.__SKIP__:
                continue
            if i not in e or self[i] != e[i]:
                return False

        if self.__NEXT__ in self.itemlist:
            return self[self.__NEXT__] == e.next()

        return True

    def __bytes__(self):
        b = b''
        b += self.convert(self.__DST__)
        b += self.convert(self.__SRC__)
        b += self.convert(self.__TYPE__)
        b += self.getnext()
        self[self.__BYTES__] = b
        return b

    def moops_keys(self):
        k = self.__KEYS__
        for i in self.keys():
            k += [i]
        return k

    def next(self):
        if self.__NEXTDATA__ not in self.itemlist:
            return b''
        return self[self.__NEXTDATA__]

    def setnext(self, x):
        self[self.__NEXT__] = x
        return x

    def getnext(self):
        if self.__NEXT__ not in self.itemlist:
            return b''
        return bytes(self[self.__NEXT__])

    def parse(self):
        if self.__BYTES__ not in self.itemlist:
            self.__bytes__()

        if len(self[self.__BYTES__]) < 14:
            raise Exception("Invalid packet length")

        # A temporary store for parsing
        self[self.__INT_PTR__] = 0

        self.parsemac(self.__DST__)
        self.parsemac(self.__SRC__)
        self.parsetype()

        # If we have excess data, try out the next type
        p = self[self.__INT_PTR__]
        self[self.__NEXTDATA__] = self[self.__BYTES__][p:]

        # Delete our unneeded key
        self.pop(self.__INT_PTR__, None)

    def parsemac(self, n):
        p = self[self.__INT_PTR__]

        s = ''
        for i in self[self.__BYTES__][p:p+6]:
            s += "{:02x}:".format(i)

        self[self.__INT_PTR__] = p + 6
        self[n] = s[0:-1]

    def parsetype(self):
        p = self[self.__INT_PTR__]
        s = int.from_bytes(self[self.__BYTES__][p:p+2], "big")
        self['type'] = s
        self[self.__INT_PTR__] = p + 2

    def convert(self, n):
        if n == self.__SRC__ or n == self.__DST__:
            return self.convertmac(n)
        elif n == self.__TYPE__:
            return self.converttype(n)
        else:
            raise Exception('Unknown token')

    def convertmac(self, n):
        if n not in self.itemlist:
            return self.__EMPTY__

        b = b''
        v = self[n]
        for i in v.split(':'):
            b += bytes([int(i, 16)])

        return b

    def converttype(self, n):
        if n not in self.itemlist:
            return b'\x08\x00'

        x = self[n]
        return bytes([(x >> 8) & 0xff, x & 0xff])
