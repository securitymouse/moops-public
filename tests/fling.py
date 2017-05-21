from moops.ether import Ether as E
from moops.ip import IP 
from moops.udp import UDP
from moops.fling import Fling as F
from moops.match import Match as M
from moops.mangle import Mangle
import socket
import time
import sys


def mangle(x):
    e = E({'bytes': x})
    i = IP({'bytes': e.next(), 'prev': e})
    u = UDP({'bytes': i.next(), 'prev': i})
    e['next'] = i
    i['next'] = u

    e['src'] = '00:11:22:33:44:55'
    i['src'] = '192.168.127.3'

    print("fling: {0} -> {1}".format(i['src'], i['dst']))

    return bytes(e)


print("\nFling test")
u = UDP()
u['dst'] = 1234
i = IP({'next': u})
i['dst'] = "123.1.1.2"
e = E({'next': i})
e['dst'] = "a0:bb:cc:dd:ee:f0"
m = M()
m['match'] = e
print(e)
print(i)
print(u)

#f = F({'in': 'wlp3s0', 'out': 'enp0s31f6'})
f = F({'in': 'wlx8416f91a27ec', 'out': 'wlp3s0'})
f['match'] = m
f['mangle'] = mangle
print("running?")
f.start()
while(1):
    time.sleep(50)
print("joining?")
f.join()
print("done")
