/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_BROADCAST = 0x1234;
const bit<6> TCP_SYN = 0x02;
const bit<6> TCP_SYNACK = 0x12;
const bit<6> TCP_ACK = 0x10;
const bit<6> TCP_RST = 0x04;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct learn_t {
    bit<4> digest_type;
    bit<48> srcAddr;
    bit<9>  ingress_port;
}

struct white_entry_t{
    bit<4> digest_type;
    bit<32> srcAddr;
}

struct metadata {
    learn_t learn;
    white_entry_t white_entry;
    bit<16> tcpLength;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t            ipv4;
    tcp_t              tcp;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = (bit<16>)(hdr.ipv4.totalLen - 16w20);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {

        mark_to_drop(standard_metadata);
    }

    action mac_learn(){
        meta.learn.digest_type=1;
        meta.learn.srcAddr = hdr.ethernet.srcAddr;
        meta.learn.ingress_port = standard_metadata.ingress_port;
        digest<learn_t>(1, meta.learn);
    }
    
    action modify_syn_to_synack(bit<32> check_seq) {
        // Swap ip
        hdr.ipv4.srcAddr=hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr=hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        hdr.ipv4.srcAddr=hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        // Swap mac
        hdr.ethernet.srcAddr=hdr.ethernet.srcAddr ^ hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr=hdr.ethernet.srcAddr ^ hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr=hdr.ethernet.srcAddr ^ hdr.ethernet.dstAddr;
        // Swap port
        hdr.tcp.srcPort=hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        hdr.tcp.dstPort=hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        hdr.tcp.srcPort=hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        // Set tcp flags
        hdr.tcp.ctrl=TCP_SYNACK;
        // Set new seqNo
        hdr.tcp.seqNo=hdr.tcp.seqNo+1;
        // Set ack number
        hdr.tcp.ackNo=hdr.tcp.seqNo;
        // Set seq number
        hdr.tcp.seqNo=check_seq;
        standard_metadata.egress_spec =standard_metadata.ingress_port;
    }

    action modify_ack_to_rst() {
        // Info the controller
        meta.white_entry.digest_type=2;
        meta.white_entry.srcAddr=hdr.ipv4.srcAddr;
        digest<white_entry_t>(1, meta.white_entry);
        // Swap ip
        hdr.ipv4.srcAddr=hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr=hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        hdr.ipv4.srcAddr=hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        // Swap mac
        hdr.ethernet.srcAddr=hdr.ethernet.srcAddr ^ hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr=hdr.ethernet.srcAddr ^ hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr=hdr.ethernet.srcAddr ^ hdr.ethernet.dstAddr;
        // Swap port
        hdr.tcp.srcPort=hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        hdr.tcp.dstPort=hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        hdr.tcp.srcPort=hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        // Set tcp flags
        hdr.tcp.ctrl=TCP_RST;
        hdr.tcp.seqNo=hdr.tcp.ackNo;
        standard_metadata.egress_spec =standard_metadata.ingress_port; 
    }

    table white_list {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions={
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    table check_syn {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.tcp.srcPort: ternary;
        }
        actions={
            modify_syn_to_synack();
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    table check_ack {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.tcp.srcPort: ternary;
            hdr.tcp.ackNo:exact;
        }
        actions={
            modify_ack_to_rst();
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    table smac {

        key = {
            hdr.ethernet.srcAddr: exact;
        }

        actions = {
            mac_learn;
            NoAction;
        }
        size = 256;
        default_action = mac_learn;
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    table broadcast {
        key = {
            standard_metadata.ingress_port: exact;
        }

        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        smac.apply();
        if(white_list.apply().hit || !hdr.tcp.isValid()) {
            if (dmac.apply().hit){
            //
            }
            else {
                broadcast.apply();
            }
        }
        else if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if(hdr.tcp.ctrl==TCP_SYN) {
                check_syn.apply();
            } else if (hdr.tcp.ctrl == TCP_ACK ) {
                if(check_ack.apply().hit) {

                }else {
                    drop();
                }
            } else {
                drop();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(true, 
            { hdr.ipv4.version,
            hdr.ipv4.ihl, 
            hdr.ipv4.diffserv, 
            hdr.ipv4.totalLen, 
            hdr.ipv4.identification, 
            hdr.ipv4.flags, 
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl, 
            hdr.ipv4.protocol, 
            hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr}, 
            hdr.ipv4.hdrChecksum, 
            HashAlgorithm.csum16);

        update_checksum_with_payload(
        hdr.tcp.isValid(), 
        {hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        8w0,
        hdr.ipv4.protocol,
        meta.tcpLength,
        hdr.tcp.srcPort,
        hdr.tcp.dstPort,
        hdr.tcp.seqNo,
        hdr.tcp.ackNo,
        hdr.tcp.dataOffset,
        hdr.tcp.res,
        hdr.tcp.ecn,
        hdr.tcp.ctrl,
        hdr.tcp.window,
        hdr.tcp.urgentPtr},
        hdr.tcp.checksum,
        HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;