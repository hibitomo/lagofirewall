#!/usr/bin/python

"""
Lagopus Firewall tester

                    +------------+
                    |            |
                    | tester.py  |
                    |            |
                    +-----+------+
                          |  localhost:6654
         +----------------+----------------+
         |                                 |
         |          +------------+         |
         |          |            |         |
         |          | lagopus_fw |         |
         |          |            |         |
         |          +-----+------+         |
         |                | localhost:6653 |
         |                |                |         Remote Controller
+----------------------------------------------------------------------+
         |                |                |         mininet
         |          +-----+-----+          |
         |          |           |          |
   +-----+-----+    |    s1     |    +-----+-----+
   |           |    | (Lagopus) |    |           |
   |           +----+           +----+           |
   |    s2     |    +-----------+    |    s3     |
   | (Lagopus) |                     | (Lagopus) |
   |           +---------------------+           |
   |           |                     |           |
   +-----------+                     +-----------+

"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.node import Lagopus
from mininet.cli import CLI

c0 = RemoteController(name='c0', ip='127.0.0.1' )
c1 = RemoteController(name='c1', ip='127.0.0.1', port=6654)
cmap = {'s1': c0, 's2': c1, 's3': c1}

class SimpleLagopusTopo(Topo):

    def __init__(self):
        "Set Lagopus as a default switch class"
        Topo.__init__(self, sopts={ "cls" : MultiSwitch })

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        self.addLink(s1, s3)
        self.addLink(s2, s1)
        self.addLink(s2, s3)
        

class MultiSwitch( Lagopus ):
    def start( self, controllers ):
        print cmap[ self.name ]
        return Lagopus.start(self, [ cmap[ self.name ] ])

def lagopusTest():
    "Create network topology with Lagopus OFS and check connections"
    topo = SimpleLagopusTopo()

    """ Set contoroller class in order to
        use external OpenFlow 1.3 controller """
    net = Mininet( topo=topo,
                   switch=MultiSwitch )

    net.start()

    print "Checking whether switch class is Lagopus"
    for s in net.switches:
        print repr(s)

    print "Testing connections"
    net.pingAll()

    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    lagopusTest()
