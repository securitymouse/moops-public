import socket


class IP(dict):
    # Our dictionary, so it's easy to access
    __VERSION__ = "version"
    __IHL__ = "ihl"
    __TOS__ = "tos"
    __LENGTH__ = "length"
    __IDENT__ = "ident"
    __FLAGS__ = "flags"
    __OFFSET__ = "offset"
    __TTL__ = "ttl"
    __PROTOCOL__ = "protocol"
    __CHECKSUM__ = "checksum"
    __SRC__ = "src"
    __DST__ = "dst"
    __OPTIONS__ = "options"
    __NEXT__ = "next"
    __NAME__ = "name"

    # Not "exported"; internal use only
    __BYTES__ = "bytes"
    __INT_PTR__ = "__ptr"
    __INT_OPTIONS__ = "__options"
    __LOCALHOST__ = "127.0.0.1"
    __INT_FOFF__ = "__foff"
    __DEFAULT_TTL__ = 128
    __NEXTDATA__ = "__next"

    __KEYS__ = [
        __VERSION__,
        __IHL__,
        __TOS__,
        __LENGTH__,
        __IDENT__,
        __FLAGS__,
        __OFFSET__,
        __TTL__,
        __PROTOCOL__,
        __CHECKSUM__,
        __SRC__,
        __DST__,
        __OPTIONS__,
        __NEXT__,
        __NAME__
        ]

    __SKIP__ = [
        __NEXT__,
        __NAME__,
        __BYTES__,
        __NEXTDATA__
        ]

    __EMPTY__ = bytes(6)

    itemlist = None
    inbound = False

    def __init__(self, *args, **kw):
        dict.__init__(self, *args, **kw)
        self.itemlist = super(IP, self).keys()
        self[self.__NAME__] = "IP"

        # Auto-parse if we have bytes
        if self.__BYTES__ in self.itemlist:
            self.inbound = True
            self.parse()

    def __hash__(self):
        return hash(tuple(sorted(self.items())))

    def __eq__(self, x):
        ip = IP({self.__BYTES__: x})
        ip.parse()
        for i in self.itemlist:
            if i in self.__SKIP__:
                continue
            if i not in ip or self[i] != ip[i]:
                return False

            if self.__NEXT__ in self.itemlist:
                return self[self.__NEXT__] == ip.next()

        return True

    def __bytes__(self):
        # First, so we know the packet size, do the following
        self.generate_options()
        self.update_ihl()

        # Now, generate the summable header
        b = b''
        b += self.convert_vhl()
        b += self.convert_tos()
        b += self.convert_length()
        b += self.convert_ident()
        b += self.convert_flags()
        b += self.convert_ttl()
        b += self.convert_protocol()
        b += b'\x00\x00'
        b += self.convert_src()
        b += self.convert_dst()
        b += self.convert_options()

        # Now, generate the checksum if desired
        c = self.convert_checksum(b)
        b = b[0:10] + bytes([((c >> 8) & 0xff), (c & 0xff)]) + b[12:]

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

    def setnext(self, x):
        self[self.__NEXT__] = x
        return x

    def getnext(self):
        if self.__NEXT__ not in self.itemlist:
            return b''
        return bytes(self[self.__NEXT__])

    def get_datalength(self):
        l = 0
        if self.__NEXT__ in self.itemlist:
            p = self[self.__NEXT__]
            l = len(bytes(p))
        return l

    def pad_data(self, n):
        # This presumes that the Next module can handle a byte add
        if self.__NEXT__ in self.itemlist:
            p = self[self.__NEXT__]
            p += bytes(n)
            self[self.__NEXT__] = p

    def generate_options(self):
        self[self.__INT_OPTIONS__] = b''
        if self.__OPTIONS__ not in self.itemlist:
            return

        # Options should be a list of bytes
        o = self[self.__OPTIONS__]
        x = b''
        for i in o:
            x += i
        self[self.__INT_OPTIONS__] = x

    def convert_options(self):
        o = self[self.__INT_OPTIONS__]
        self.pop(self.__INT_OPTIONS__, None)
        return o

    def convert_src(self):
        a = self.__LOCALHOST__
        if self.__SRC__ in self.itemlist:
            a = self[self.__SRC__]
        return socket.inet_aton(a)

    def convert_dst(self):
        a = self.__LOCALHOST__
        if self.__DST__ in self.itemlist:
            a = self[self.__DST__]
        return socket.inet_aton(a)

    def generate_checksum(self, b):
        s = 0
        i = 0
        c = len(b)
        while c > 1:
            s += int.from_bytes(b[i:i+2], "big")
            i += 2
            c -= 2

        if c > 0:
            s += int.from_bytes(b[i], "big")

        while (s >> 16) != 0:
            s = (s & 0xffff) + (s >> 16)

        return ~s

    # Generate a pseudo header for TCP or UDP
    def pseudoheader(self, l):
        b = b''
        b += self.convert_src()
        b += self.convert_dst()
        b += b'\x00'
        b += self.convert_protocol()
        b += bytes([(l >> 8) & 0xff, (l & 0xff)])
        return b

    def update_ihl(self):
        # First, see if we have any options
        l = len(self[self.__INT_OPTIONS__])
        if l == 0:
            return

        # We have options. It's the user's responsibility to create a padded
        # packet, so we just calculate the value with the data we have
        if l % 4 != 0:
            l = 4 * int((l + 4) / 4)

        l = int((l + 21) / 4)

        # Even though convert_vhl checks this, do it now so we know the context
        # in which it failed.
        if l < 0 or l > 15:
            raise Exception("Updated IHL out of bounds")

        self[self.__IHL__] = l

    def convert_vhl(self):
        v = 4
        if self.__VERSION__ in self.itemlist:
            v = int(self[self.__VERSION__])

        l = 5
        if self.__IHL__ in self.itemlist:
            l = int(self[self.__IHL__])
        else:
            self[self.__IHL__] = l

        if v < 0 or v > 15:
            raise Exception("Invalid version")
        if l < 0 or l > 15:
            raise Exception("Invalid ihl")

        return bytes([(v << 4) | (l)])

    def convert_tos(self):
        t = 0
        if self.__TOS__ in self.itemlist:
            t = int(self[self.__TOS__])

        if t < 0 or t > 255:
            raise Exception("Invalid TOS")

        return bytes([t])

    def convert_length(self):
        x = 0
        # Calculate the size of the full packet if the user doesn't want a
        # specific length.
        if self.__LENGTH__ not in self.itemlist or self.inbound:
            h = self[self.__IHL__] * 4
            d = self.get_datalength()
            x = h + d

            # handle if the padding is off
            if (x & 1):
                x += 1
                self.pad_data(1)
        else:
            x = self[self.__LENGTH__]

        return bytes([((x >> 8) & 0xff), (x & 0xff)])

    def convert_ident(self):
        x = 0
        if self.__IDENT__ in self.itemlist:
            x = self[self.__IDENT__]

        return bytes([((x >> 8) & 0xff), (x & 0xff)])

    # This consists of both Flags and Fragment Offset
    def convert_flags(self):
        f = 0
        if self.__FLAGS__ in self.itemlist:
            f = self[self.__FLAGS__]
        o = 0
        if self.__OFFSET__ in self.itemlist:
            o = self[self.__OFFSET__]

        x = ((f & 0x07) << 13) | o

        return bytes([((x >> 8) & 0xff), (x & 0xff)])

    def convert_ttl(self):
        t = self.__DEFAULT_TTL__
        if self.__TTL__ in self.itemlist:
            t = self[self.__TTL__]
        return bytes([t])

    def convert_protocol(self):
        # UDP by default
        x = 17
        if self.__PROTOCOL__ in self.itemlist:
            x = self[self.__PROTOCOL__]
        return bytes([x])

    def convert_checksum(self, b):
        c = 0
        if self.__CHECKSUM__ not in self.itemlist or self.inbound:
            c = self.generate_checksum(b)
        else:
            c = self[self.__CHECKSUM__]
        return c

    def parse(self):
        if self.__BYTES__ not in self.itemlist:
            self.__bytes__()

        # While we can theoretically send an invalid or short packet, there is
        # little value in parsing a packet that isn't full (some exceptions)
        if len(self[self.__BYTES__]) < 20:
            raise Exception("Invalid packet length")

        self[self.__INT_PTR__] = 0

        self.parsevhl()
        self.parsebyte(self.__TOS__)
        self.parseshort(self.__LENGTH__)
        self.parseshort(self.__IDENT__)
        self.parseflags()
        self.parsebyte(self.__TTL__)
        self.parsebyte(self.__PROTOCOL__)
        self.parseshort(self.__CHECKSUM__)
        self.parseaddr(self.__SRC__)
        self.parseaddr(self.__DST__)
        self.parseoptions()
        self.parsenext()

        self.pop(self.__INT_PTR__, None)

    def parsevhl(self):
        p = self[self.__INT_PTR__]

        x = self[self.__BYTES__][p]
        self[self.__VERSION__] = (x >> 4) & 0x0f
        self[self.__IHL__] = (x & 0x0f)

        self[self.__INT_PTR__] = p + 1

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

    def parseflags(self):
        self.parseshort(self.__INT_FOFF__)
        x = self[self.__INT_FOFF__]
        self[self.__FLAGS__] = (x >> 13) & 0x07
        self[self.__OFFSET__] = x & 0x1fff
        self.pop(self.__INT_FOFF__, None)

    # We keep this as an unparsed array because we may not want to raise an
    # error if something is wrong in the formatting.
    # Also, this is very lazy. We don't check for extra data or even if the
    # payload length matches what the header defines.
    def parseoptions(self):
        # Always go by the header length to get the option boundary
        l = self[self.__IHL__]
        if (l * 4) <= 20:
            return

        l = (l * 4) - 20

        p = self[self.__INT_PTR__]
        self[self.__OPTIONS__] = [self[self.__BYTES__][p:p+l]]
        self[self.__INT_PTR__] = p + l

    def parsenext(self):
        p = self[self.__INT_PTR__]
        self[self.__NEXTDATA__] = self[self.__BYTES__][p:]
        self[self.__INT_PTR__] = p + len(self[self.__NEXTDATA__])

    def parseaddr(self, n):
        p = self[self.__INT_PTR__]
        self[n] = socket.inet_ntoa(self[self.__BYTES__][p:p+4])
        self[self.__INT_PTR__] = p + 4

