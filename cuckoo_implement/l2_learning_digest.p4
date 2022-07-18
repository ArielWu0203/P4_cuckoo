/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_BROADCAST = 0x1234;
const bit<6> TCP_SYN = 0x02;
const bit<6> TCP_SYNACK = 0x12;
const bit<6> TCP_ACK = 0x10;
const bit<6> TCP_RST = 0x04;


#define REGISTER_LENGTH 301
#define CUCKOO_ROW_LENGTH  75
#define T 5

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

struct black_entry_t {
    bit<4> digest_type;
    bit<32> index;
    bit<32> srcAddr;
}

struct slot_t {
    bit<48> dst_mac;
    bit<32> src_ip;
    bit<16> count;
}

struct metadata {
    learn_t learn;
    white_entry_t white_entry;
    black_entry_t black_entry;
    bit<16> tcpLength;
    slot_t read_slot;
    slot_t write_slot;
    bit<32> insert_index;
    bit<8> rand_0;
    bit<8> rand_1;
    bit<8> rand_2;
    bit<8> rand_3;
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

    register<bit <48>>(REGISTER_LENGTH) cuckoo_register_mac;
    register<bit <32>>(REGISTER_LENGTH) cuckoo_register_ip;
    register<bit <16>>(REGISTER_LENGTH) cuckoo_register_count;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mac_learn(){
        meta.learn.digest_type=1;
        meta.learn.srcAddr = hdr.ethernet.srcAddr;
        meta.learn.ingress_port = standard_metadata.ingress_port;
        digest<learn_t>(1, meta.learn);
    }

    action cuckoo_read(bit<32> index) {
        cuckoo_register_mac.read(meta.read_slot.dst_mac, index);
        cuckoo_register_ip.read(meta.read_slot.src_ip, index);
        cuckoo_register_count.read(meta.read_slot.count, index);
    }
    action cuckoo_write(bit<32> index, slot_t slot) {
        cuckoo_register_mac.write(index, slot.dst_mac);
        cuckoo_register_ip.write(index, slot.src_ip);
        cuckoo_register_count.write(index, slot.count);
    }

    action swap_field() {
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
    }

    action modify_syn_to_synack(bit<32> check_seq) {
        swap_field();
        // Set tcp flags
        hdr.tcp.ctrl=TCP_SYNACK;
        // Set new seqNo
        hdr.tcp.seqNo=hdr.tcp.seqNo+1;
        // Set ack number
        hdr.tcp.ackNo=hdr.tcp.seqNo;
        // Set seq number
        hdr.tcp.seqNo=check_seq;

        /* Add to cuckoo */

        /* Init variables */
        meta.write_slot={hdr.ethernet.dstAddr, hdr.ipv4.srcAddr, 16w1};
        // cuckoo register's info
        bit<32> now_column=0;
        bit<1> empty_flag=0;
        bit<32> empty_index=0;
        bit<1> find_flag=0;
        meta.insert_index=REGISTER_LENGTH-1;

        bit <32> hash_value=0;
        /* First column */
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {hdr.ethernet.dstAddr, hdr.ipv4.srcAddr, meta.rand_0}, (bit<32>)CUCKOO_ROW_LENGTH);
        bit<32> now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if(empty_flag==0 && meta.read_slot.count==0) {
            empty_flag=1;
            empty_index=now_index;
        } else if (find_flag ==0 && meta.read_slot.dst_mac==meta.write_slot.dst_mac && meta.read_slot.src_ip==meta.write_slot.src_ip) {
            meta.write_slot.count=meta.read_slot.count+1;
            meta.insert_index=now_index;
            find_flag=1;
        }

        /* Second column*/
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {hdr.ethernet.dstAddr, hdr.ipv4.srcAddr, meta.rand_1}, (bit<32>)CUCKOO_ROW_LENGTH);
        now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if(empty_flag==0 && meta.read_slot.count==0) {
            empty_flag=1;
            empty_index=now_index;
        } else if (find_flag ==0 && meta.read_slot.dst_mac==meta.write_slot.dst_mac && meta.read_slot.src_ip==meta.write_slot.src_ip) {
            meta.write_slot.count=meta.read_slot.count+1;
            meta.insert_index=now_index;
            find_flag=1;
        }

        /* Third column*/
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {hdr.ethernet.dstAddr, hdr.ipv4.srcAddr, meta.rand_2}, (bit<32>)CUCKOO_ROW_LENGTH);
        now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if(empty_flag==0 && meta.read_slot.count==0) {
            empty_flag=1;
            empty_index=now_index;
        } else if (find_flag ==0 && meta.read_slot.dst_mac==meta.write_slot.dst_mac && meta.read_slot.src_ip==meta.write_slot.src_ip) {
            meta.write_slot.count=meta.read_slot.count+1;
            meta.insert_index=now_index;
            find_flag=1;
        }

        /* Forth column*/
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {hdr.ethernet.dstAddr, hdr.ipv4.srcAddr, meta.rand_3}, (bit<32>)CUCKOO_ROW_LENGTH);
        now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if(empty_flag==0 && meta.read_slot.count==0) {
            empty_flag=1;
            empty_index=now_index;
        } else if (find_flag ==0 && meta.read_slot.dst_mac==meta.write_slot.dst_mac && meta.read_slot.src_ip==meta.write_slot.src_ip) {
            meta.write_slot.count=meta.read_slot.count+1;
            meta.insert_index=now_index;
            find_flag=1;
        }
        /* Insert item*/
        if(find_flag==0 && empty_flag==1) {
            meta.insert_index=empty_index;
        }
        cuckoo_write(meta.insert_index, meta.write_slot);
    }
    action clear_the_slot(bit<48> mac, bit<32> ip) {
        /* Clear the slot*/

        /* Init variables */
        slot_t slot={mac, ip, 16w0};
        // cuckoo register's info
        bit<32> now_column=0;
        bit<32> insert_index=REGISTER_LENGTH-1;
        bit<1> find_flag=0;

        bit <32> hash_value;
        /* First column */
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {mac, ip, meta.rand_0}, (bit<32>)CUCKOO_ROW_LENGTH);
        bit<32> now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if (find_flag==0 && meta.read_slot.dst_mac==slot.dst_mac && meta.read_slot.src_ip==slot.src_ip) {
            insert_index=now_index;
            find_flag=1;
        }

        /* Second column*/
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {mac, ip, meta.rand_1}, (bit<32>)CUCKOO_ROW_LENGTH);
        now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if (find_flag==0 && meta.read_slot.dst_mac==slot.dst_mac && meta.read_slot.src_ip==slot.src_ip) {
            insert_index=now_index;
            find_flag=1;
        }

        /* Third column*/
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {mac, ip, meta.rand_2}, (bit<32>)CUCKOO_ROW_LENGTH);
        now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if (find_flag==0 && meta.read_slot.dst_mac==slot.dst_mac && meta.read_slot.src_ip==slot.src_ip) {
            insert_index=now_index;
            find_flag=1;
        }

        /* Forth column*/
        hash(hash_value, HashAlgorithm.crc32, (bit<32>) 0, {mac, ip, meta.rand_3}, (bit<32>)CUCKOO_ROW_LENGTH);
        now_index=now_column*CUCKOO_ROW_LENGTH + hash_value;
        now_column=now_column+1;
        cuckoo_read(now_index);
        if (find_flag==0 && meta.read_slot.dst_mac==slot.dst_mac && meta.read_slot.src_ip==slot.src_ip) {
            insert_index=now_index;
            find_flag=1;
        }

        /* Insert item*/
        slot.dst_mac=48w0;
        slot.src_ip=32w0;
        cuckoo_write(insert_index, slot);
    }
    action modify_ack_to_rst() {
        // Info the controller
        meta.white_entry.digest_type=2;
        meta.white_entry.srcAddr=hdr.ipv4.srcAddr;
        digest<white_entry_t>(1, meta.white_entry);
        swap_field();

        // Set tcp flags
        hdr.tcp.ctrl=TCP_RST;
        hdr.tcp.seqNo=hdr.tcp.ackNo;

        clear_the_slot(hdr.ethernet.dstAddr, hdr.ipv4.srcAddr);

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

    table black_list {
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

        meta.rand_0=0;
        meta.rand_1=17;
        meta.rand_2=29;
        meta.rand_3=37;

        smac.apply();
        if(black_list.apply().hit) {
            if(hdr.tcp.isValid() && hdr.tcp.ctrl==TCP_SYN) {
                clear_the_slot(hdr.ethernet.srcAddr, hdr.ipv4.dstAddr);
            }
            drop();
        }
        else if(white_list.apply().hit || !hdr.tcp.isValid()) {
            if (dmac.apply().hit){
            //
            }
            else {
                broadcast.apply();
            }
        }
        else if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if(hdr.tcp.ctrl==TCP_SYN) {
                if(check_syn.apply().hit) {
                    /* Info to the controller */
                    if(meta.write_slot.count > T) {
                        /* Clear the slot */
                        meta.black_entry.digest_type=3;
                        meta.black_entry.index=meta.insert_index;
                        meta.black_entry.srcAddr=hdr.ipv4.dstAddr;
                        digest<black_entry_t>(1, meta.black_entry);
                    }
                    // Return the packet
                    standard_metadata.egress_spec =standard_metadata.ingress_port;
                }
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
