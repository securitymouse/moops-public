from moops.ether import Ether
from moops.udp import UDP
from moops.ip import IP

class Mangle(dict):
    # This is a module that should be customized on a per-effort basis. The
    # Fling module should call any Mangle object with an update() function to
    # handle the task of converting the payload into a new payload.

    __NAME__ = "name"
    __MANGLE__ = "mangle"

    __KEYS__ = [
        __NAME__,
        __MANGLE__
        ]

    itemlist = None

    def __init__(self, *args, **kw):
        dict.__init__(self, *args, **kw)
        self.itemlist = super(Mangle, self).keys()
        self[self.__NAME__] = "Mangle"

    def __hash__(self):
        return hash(tuple(sorted(self.items())))

    def moops_keys(self):
        k = self.__KEYS__
        for i in self.keys():
            k += [i]
        return k

    def update(self, x):
        e = Ether({'bytes': x})
        i = IP({'bytes': e.next(), 'prev': e})
        u = UDP({'bytes': i.next(), 'prev': i})
        e['next'] = i
        i['next'] = u

        i['src'] = '1.2.3.4'

        return bytes(e)
