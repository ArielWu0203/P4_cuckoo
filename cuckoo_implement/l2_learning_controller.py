import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.thrift_API import ThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw
import logging

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]


class L2Controller(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.cli_api = ThriftAPI(self.thrift_port, '127.0.0.1', 'none')
        logging.basicConfig(filename="digest.log", level=logging.INFO, filemode='w')
        self.init()

    def init(self):
        self.controller.reset_state()
        self.add_boadcast_groups()
        self.add_mirror()
        self.fill_table_test()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def add_boadcast_groups(self):
        interfaces_to_port = self.topo.get_node_intfs(fields=['port'])[self.sw_name].copy()
        # Filter lo and cpu port
        interfaces_to_port.pop('lo', None)
        interfaces_to_port.pop(self.topo.get_cpu_port_intf(self.sw_name), None)

        mc_grp_id = 1
        rid = 0
        for ingress_port in interfaces_to_port.values():
            port_list = list(interfaces_to_port.values())
            del(port_list[port_list.index(ingress_port)])
            #add multicast group
            self.controller.mc_mgrp_create(mc_grp_id)
            #add multicast node group
            handle = self.controller.mc_node_create(rid, port_list)
            #associate with mc grp
            self.controller.mc_node_associate(mc_grp_id, handle)
            #fill broadcast table
            self.controller.table_add("broadcast", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])
            mc_grp_id +=1
            rid +=1

    def fill_table_test(self):
        self.controller.table_add("white_list", "NoAction", ["10.0.0.1"])
        seq=100
        for ip_mask in ['0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
            for port_mask in ['0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
                seq_str='0x'+f'{seq:04x}'
                ack_str='0x'+f'{seq+1:04x}'
                self.controller.table_add("check_ack", "modify_ack_to_rst", ['0x00000%s00&&&0x00000f00'%ip_mask, '0x00%s0&&&0x00f0'%port_mask, ack_str])
                self.controller.table_add("check_syn", "modify_syn_to_synack", ['0x00000%s00&&&0x00000f00'%ip_mask, '0x00%s0&&&0x00f0'%port_mask], [seq_str])
                seq+=1
        
    def learn(self, learning_data):
        for mac_addr, ingress_port in  learning_data:
            logging.info("learn mac: %012X ingress_port: %s\n" % (mac_addr, ingress_port))
            self.controller.table_add("smac", "NoAction", [str(mac_addr)])
            self.controller.table_add("dmac", "forward", [str(mac_addr)], [str(ingress_port)])

    def add_white_list(self, data):
        for ip in data:
            logging.info("white ip: %8X" % ip)
            self.controller.table_add("white_list", "NoAction", [str(ip)])
    
    def add_black_list(self, data):
        for index, ip in data:
            logging.info("black ip: %8X" % ip)
            self.controller.table_add("black_list", "NoAction", [str(ip)])
            self.cli_api.register_write("MyIngress.cuckoo_register_mac", index, 0)
            self.cli_api.register_write("MyIngress.cuckoo_register_ip", index, 0)
            self.cli_api.register_write("MyIngress.cuckoo_register_count", index, 0)

    def unpack_digest(self, msg, num_samples):
        learn_digest = []
        white_list_digest = []
        black_list_digest = []
        starting_index = 32
        # logging.info("nums:%d" % num_samples)
        # logging.info("msg_len:%d" % len(msg[32:]))
        # # logging.info("msg")
        # logging.info(msg[32:])
        for sample in range(num_samples):
            digest_type, = struct.unpack("!B", msg[starting_index:starting_index+1])
            starting_index +=1
            if(digest_type==1):
                mac0, mac1, ingress_port = struct.unpack(">LHH", msg[starting_index:starting_index+8])
                starting_index +=8
                mac_addr = (mac0 << 16) + mac1
                learn_digest.append((mac_addr, ingress_port))
            elif(digest_type==2): # white list
                ip, =struct.unpack(">L", msg[starting_index: starting_index+4])
                starting_index +=4
                white_list_digest.append((ip))
            elif(digest_type==3): # black list
                index, ip=struct.unpack(">LL", msg[starting_index: starting_index+8])
                starting_index +=8
                black_list_digest.append((index, ip))
        return learn_digest, white_list_digest, black_list_digest

    def recv_msg_digest(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        learn_digest, white_list_digest, black_list_digest = self.unpack_digest(msg, num)
        self.learn(learn_digest)
        self.add_white_list(white_list_digest)
        self.add_black_list(black_list_digest)
        #Acknowledge digest
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)

    def recv_msg_cpu(self, pkt):
        packet = Ether(raw(pkt))
        if packet.type == 0x1234:
            cpu_header = CpuHeader(bytes(packet.load))
            self.learn([(cpu_header.macAddr, cpu_header.ingress_port)])

    def run_cpu_port_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)


if __name__ == "__main__":
    import sys
    sw_name = sys.argv[1]
    receive_from = sys.argv[2]
    if receive_from == "digest":
        controller = L2Controller(sw_name).run_digest_loop()
    elif receive_from == "cpu":
        controller = L2Controller(sw_name).run_cpu_port_loop()
