class Match(dict):

    __NAME__ = "name"
    __MATCH__ = "match"

    __KEYS__ = [
        __NAME__,
        __MATCH__
        ]

    itemlist = None

    def __init__(self, *args, **kw):
        dict.__init__(self, *args, **kw)
        self.itemlist = super(Match, self).keys()
        self[self.__NAME__] = "Match"

    def __hash__(self):
        return hash(tuple(sorted(self.items())))

    def moops_keys(self):
        k = self.__KEYS__
        for i in self.keys():
            k += [i]
        return k

    def __eq__(self, x):
        return self[self.__MATCH__] == x
