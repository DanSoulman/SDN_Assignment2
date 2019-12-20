# Dan Coleman R00151926 SDN Assignment 2
#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Controller, RemoteController
from mininet.link import TCLink
from mininet.util import irange, dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from itertools import repeat
from copy import deepcopy

# GLOBALS
CORE_SWITCH_COUNT = 4  # No of Core Switches in Topology
EDGE_SWITCH_COUNT = 16  # No of edge Switches in Topology

class CustomTopo(Topo):
    # default if value is not declared
    def __init__(self, NO_OF_CORE_SWITCHES=4, NO_OF_EDGE_SWITCHES=16, **opts):

        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Variables
        core_switch_list = []  # Holds list of CORE switches
        temp = list(repeat(0,NO_OF_CORE_SWITCHES)) #list of size specified gloabally (in this case 4)
        edge_switch_list = [deepcopy(temp) for i in range(0,NO_OF_CORE_SWITCHES)] # 4 lists for the 4 edge "pods"
        dpid_template = "0000000000" #Template used to number dpid
        pod_count = 0 #Used to increment dpids

        # Creates a list of Core switches and numbers them
        for i in irange(1, NO_OF_CORE_SWITCHES):
            core_switch_list.append(self.addSwitch("C%s1" % i, dpid=dpid_template+"C"+str(i)))

        # Creates a list of Edge switches and numbers them
        for switch_list in edge_switch_list:
            pod_count += 1
            for i in irange(1, len(switch_list)):
                switch_list[i-1] = self.addSwitch("E"+str(pod_count)+str(i), dpid=dpid_template+str(pod_count)+str(i))
                host = self.addHost('H%s%s' % (pod_count, i), ip="10.0.0." +str(pod_count) + str(i))
                self.addLink(switch_list[i-1], host)
                
        # Link Switches in pod to one another 
        for switch_list in edge_switch_list:
            for i in range(0, (len(switch_list)/2)): #Links switches in group 1 to group 2
                for k in range((len(switch_list)/2), len(switch_list)):
                    self.addLink(switch_list[i], switch_list[k])

        # Connecting items in pod to core
        for switch_list in edge_switch_list:
            for i in range(0, len(switch_list)):
                self.addLink(switch_list[i], core_switch_list[i])

if __name__ == '__main__':
    setLogLevel('info')

    topo = CustomTopo(NO_OF_CORE_SWITCHES=CORE_SWITCH_COUNT,NO_OF_EDGE_SWITCHES=EDGE_SWITCH_COUNT)
    
    # Add controller 
    net = Mininet(topo=topo, autoStaticArp=True)
    controllerIP = "127.0.0.1"
    controllerPort = 6633
    pox = RemoteController('poxctrl', controllerIP, controllerPort)
    net.addController(pox)

    net.start()

    CLI(net)  # Opens CLI info
    net.stop()  # Ends mininet
