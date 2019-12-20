# R00151926 Dan Coleman
#Assignment 2 Based on sample provided ny Johnathon Sherwin

# Import POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import IPAddr          # Address types
from pox.lib.revent import *                  # Event library
import weakref                                # Weak Reference Objects
import pox.lib.util as poxutil                # Used for dpid to string

#GLOBAL VARS
SSH_PORT = 22       #ssh listens on port 22
TELNET_PORT = 23    #Telnet listens on port 23

# Create a logger for this component
log = core.getLogger()

class SwitchHandler (object):
  """
  Waits for OpenFlow switches to connect and keeps a note of the
  connection for each of them.
  """
  switches = []
  def __init__ (self):
    """
    Initialize
    """
    core.openflow.addListeners(self)

  #Function that takes in packet src, dst, and the port in and out of a given switch and sets the rule to move it along to the next switch
  def make_rule(self, source, destination, port_in, port_out):
    fm = of.ofp_flow_mod()
    fm.match.in_port = port_in
    fm.priority = 100
    fm.match.dl_type = 0x800
    fm.match.nw_src = IPAddr(source)
    fm.match.nw_dst = IPAddr(destination)
    fm.actions.append(of.ofp_action_output(port = port_out))

    return fm
    
  def _handle_ConnectionUp (self, event):
    """
    Switch connected - keep track of it by adding to the switches list
    """
    dpid_name= poxutil.dpid_to_str(event.dpid)  #Makes it a string
    self.switches.append([hex(event.dpid), weakref.ref(event.connection)])
    
    #Default Flow Rule if not specified
    base_rule = of.ofp_flow_mod()
    base_rule.priority = 0
    base_rule.hard_timeout = 0
    base_rule.idle_timeout = 0
    base_rule.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    event.connection.send(base_rule)
    
    #Flow rule 1 - H11 and H12 should be able to exchange any kind of traffic with each other (reachability functionality).  
    #======================================================================================================================  
    #Rule 1 Vars
    rule_one_source = "10.0.0.11"     #Source for host H11
    rule_one_destination = "10.0.0.12"#Source for host H14

    #E11
    if dpid_name == "00-00-00-00-00-11":
      port_in = 1   #Switch port in for E11
      port_out = 2  #Switch port out for E11

      message = self.make_rule(rule_one_source, rule_one_destination, port_in, port_out)    #Makes the rule one direction
      ret_message = self.make_rule(rule_one_destination, rule_one_source, port_out, port_in)#Makes the rule in the opposite direction for packet reply

      event.connection.send(message)    #Sends Message
      event.connection.send(ret_message)#Sends Return Message
    #E13
    elif dpid_name == "00-00-00-00-13":
      port_in = 2
      port_out = 3

      message = self.make_rule(rule_one_source, rule_one_destination, port_in, port_out)
      ret_message = self.make_rule(rule_one_destination, rule_one_source, port_out, port_in)
      event.connection.send(message)
      event.connection.send(ret_message)
    #E14
    elif dpid_name == "00-00-00-00-12":
      port_in = 2
      port_out = 1
      
      message = self.make_rule(rule_one_source, rule_one_destination, port_in, port_out)
      ret_message = self.make_rule(rule_one_destination, rule_one_source, port_out, port_in)
      event.connection.send(message)
      event.connection.send(ret_message)
    
    #Flow Rule 2 - H13 and H14 should never be able to communicate with each other (traffic isolation, similar to VLAN functionality).
    #ALREADY BLOCKED FROM TOPO 

    #Flow Rule 3. H11 should be able to telnet and SSH to H44, but no other traffic should be allowed between them (stateless firewall functionality).
    #=================================================================================================================================================
    #Rule 3 Vars
    rule_three_source = "10.0.0.11"     #Source for host H11
    rule_three_destination = "10.0.0.44"#Source for host H44

    #E11
    if dpid_name == "00-00-00-00-00-11":
      port_in = 1 #From E11-eth1<->H11-eth0
      port_out = 4 #From E11-eth4<->C11-eth1

      #SSH
      rule_three_message_ssh = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_ssh = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_ssh.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_ssh.match.tp_dst=SSH_PORT            #Filtering TCP

      event.connection.send(rule_three_message_ssh)
      event.connection.send(rule_three_ret_message_ssh)

      #TELNET
      rule_three_message_telnet = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_telnet = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_telnet.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_telnet.match.tp_dst=TELNET_PORT            #Filtering TCP

      event.connection.send(rule_three_message_telnet)
      event.connection.send(rule_three_ret_message_telnet)
    
    #C11
    elif dpid_name == "00-00-00-00-C1":
      port_in = 1 #E11-eth4<->C11-eth1
      port_out = 4 #E41-eth4<->C11-eth4 

      #SSH
      rule_three_message_ssh = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_ssh = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_ssh.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_ssh.match.tp_dst=SSH_PORT            #Filtering TCP

      event.connection.send(rule_three_message_ssh)
      event.connection.send(rule_three_ret_message_ssh)
      
      #TELNET
      rule_three_message_telnet = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_telnet = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_telnet.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_telnet.match.tp_dst=TELNET_PORT            #Filtering TCP

      event.connection.send(rule_three_message_telnet)
      event.connection.send(rule_three_ret_message_telnet)
    
    #E41
    elif dpid_name == "00-00-00-00-41":
      port_in = 4 #E41-eth4<->C11-eth4
      port_out = 3 #E41-eth3<->E44-eth2
      
      #SSH
      rule_three_message_ssh = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_ssh = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_ssh.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_ssh.match.tp_dst=SSH_PORT            #Filtering TCP

      event.connection.send(rule_three_message_ssh)
      event.connection.send(rule_three_ret_message_ssh)
      
      #TELNET
      rule_three_message_telnet = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_telnet = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_telnet.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_telnet.match.tp_dst=TELNET_PORT            #Filtering TCP

      event.connection.send(rule_three_message_telnet)
      event.connection.send(rule_three_ret_message_telnet)

    #E44
    elif dpid_name == "00-00-00-00-44":
      port_in = 2 #E41-eth3<->E44-eth2
      port_out = 1 #E44-eth1<->H44-eth0
      
      #SSH      
      rule_three_message_ssh = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_ssh = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_ssh.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_ssh.match.tp_dst=SSH_PORT            #Filtering TCP

      event.connection.send(rule_three_message_ssh)
      event.connection.send(rule_three_ret_message_ssh)

      #TELNET
      rule_three_message_telnet = self.make_rule(rule_three_source, rule_three_destination, port_in, port_out)
      rule_three_ret_message_telnet = self.make_rule(rule_three_destination, rule_three_source, port_out, port_in)
      
      rule_three_message_telnet.nw_proto = pkt.ipv4.TCP_PROTOCOL #Specifies Nw_protocol
      rule_three_message_telnet.match.tp_dst=TELNET_PORT            #Filtering TCP

      event.connection.send(rule_three_message_telnet)
      event.connection.send(rule_three_ret_message_telnet)                          
    
  # def _handle_PacketIn (self, event):
  #   Not doing Reactive.
  #   return
      
def launch():
  """  

  Call this component as, e.g.:
  ./pox.py simplefwd.py
  """

  core.registerNew(SwitchHandler)
