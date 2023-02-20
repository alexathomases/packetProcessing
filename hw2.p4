/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define NUM_PORTS 4

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_FIRST = 0x801;
const bit<16> TYPE_PROBE = 0x802;

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
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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

header first_t {
    bit<8> prot;
    bit<8> per_packet;
}

header probe_t {
    bit<32> byte_ct_2;
    bit<32> byte_ct_3;
    bit<32> switch_id;
}

struct metadata {
    bit<14> ecmp_select;
}

struct headers {
    ethernet_t   ethernet;
    first_t      first;
    ipv4_t       ipv4;
    tcp_t        tcp;
    probe_t      probe;
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
            TYPE_FIRST: parse_first;
            TYPE_PROBE: parse_probe;
            default: accept;
        }
    }

    state parse_first {
        packet.extract(hdr.first);
        transition parse_ipv4;
    }

    state parse_probe {
        packet.extract(hdr.probe);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_tcp;
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

    register<bit<32>>(NUM_PORTS) byte_ct_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action forward_probe(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action update_probe() {
        byte_ct_reg.read(hdr.probe.byte_ct_2, 2);
        byte_ct_reg.read(hdr.probe.byte_ct_3, 3);

        byte_ct_reg.write(2, 0);
        byte_ct_reg.write(3, 0);

        hdr.probe.switch_id = 1;
    }

    table probe {
        key = {
            hdr.ethernet.etherType: exact;
        }
        actions = {
            forward_probe;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        hash(meta.ecmp_select,
            HashAlgorithm.crc16,
            ecmp_base,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },
            ecmp_count);
    }
    action set_packet_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        hash(meta.ecmp_select,
            HashAlgorithm.crc16,
            ecmp_base,
            { standard_metadata.ingress_global_timestamp },
            ecmp_count);
    }
    table packet_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_packet_select;
        }
        size = 1024;
    }
    action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        hdr.ethernet.etherType = TYPE_IPV4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }
    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (hdr.first.isValid()) {
                if (hdr.first.per_packet == 0) {
                    ecmp_group.apply();
                } else {
                    packet_group.apply();
                }
                ecmp_nhop.apply();

                bit<32> byte_cnt;

                byte_ct_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_spec);
                byte_cnt = byte_cnt + (bit<32>)standard_metadata.packet_length;

                byte_ct_reg.write((bit<32>)standard_metadata.egress_spec, byte_cnt);
            } else if (hdr.probe.isValid()) {
                probe.apply();
                if (hdr.probe.switch_id == 0) {
                    update_probe();
                }
            } else {
                ipv4_lpm.apply();
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
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
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.probe);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
