#include <core.p4>
#include <psa.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;


#define MAX_REPORTS 16
#define COLLECTOR_PORT 35000
#define IP_PROTO_UDP 8w17
#define ETH_TYPE_IPV4 16w2048

const bit<32> zero = 0;
const bit<32> one = 1;
const bit<32> two = 2;
const bit<32> three = 3;
const bit<32> four = 4;
const bit<32> five = 5; 
const bit<32> six = 6; 
const bit<32> seven = 7;
const bit<32> eight = 8; 
const bit<32> nine = 9;
const bit<32> ten = 10;
const bit<32> eleven = 11;
const bit<32> twelve = 12;
const bit<32> thirteen = 13;
const bit<32> fourteen = 14; 
const bit<32> fifteen = 15;


struct empty_t {}

header ethernet_t {
    EthernetAddress dst_mac;
    EthernetAddress src_mac;
    bit<16>         etherType;
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
    bit<32> src_ip;
    bit<32> dst_ip;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}


header int_md_t {
    bit<144> one_field;
}


struct metadata {}


struct headers {
    ethernet_t                   ethernet;
    ipv4_t                      ipv4;
    udp_t                       udp;
    int_md_t                    int_md;
    int_md_t[MAX_REPORTS]       agg_reports;
}

/* The Ingress Parser */
parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        /* extract ethernet header */
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            ETH_TYPE_IPV4:  parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        /* extract IPv4 header */
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol){
            IP_PROTOCOL_UDP:   parse_udp;
            default:        accept;
        }
    }

    state parse_udp {
        /* extract UDP header */
        buffer.extract(parsed_hdr.udp);
        /* determine if this packet is carrying INT header from the DSCP field */
        transition select(parsed_hdr.ipv4.diffserv){
            DSCP_INT: parse_int;  // DSCP indicates if the packet is carrying INT
            default: accept;
        }
    }

    state parse_int {
        /* extract the shim header and INT metadata header */
        buffer.extract(parsed_hdr.int_md);
        transition accept;
    }
} // end of IngressParserImpl

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    /* a register to hold reports*/
    Register<bit<144>, bit<32>>(32w16) reg_report_buffer;
    Register<bit<64>, bit<32>>(32w1) reg_report_counter;
    bit<32> pointer; 

    action do_forward(PortId_t egress_port) {
        send_to_port(ostd, egress_port);
    }

    table tbl_fwd {
        key = {
            hdr.ethernet.dstAddr : lpm;
        }
        actions = { do_forward; NoAction; }
        default_action = NoAction;
        size = 100;
    } 
    apply {
        if (hdr.int_md.isValid()){
            zero = 0;
            one = 1;
            two = 2;
            three 
            pointer = reg_report_counter.read(zero);
            reg_report_buffer.write(pointer, hdr.int_md.one_field);
            if (pointer == fifteen ) {
                hdr.agg_reports[zero].setValid();
                hdr.agg_reports[one].setValid();
                hdr.agg_reports[two].setValid();
                hdr.agg_reports[three].setValid();
                hdr.agg_reports[four].setValid();
                hdr.agg_reports[five].setValid();
                hdr.agg_reports[six].setValid();
                hdr.agg_reports[seven].setValid();
                hdr.agg_reports[eight].setValid();
                hdr.agg_reports[nine].setValid();
                hdr.agg_reports[ten].setValid();
                hdr.agg_reports[eleven].setValid();
                hdr.agg_reports[twelve].setValid();
                hdr.agg_reports[thirteen].setValid();
                hdr.agg_reports[fourteen].setValid();
                hdr.agg_reports[fifteen].setValid();

                hdr.agg_reports[zero] = reg_report_buffer.read(zero);
                hdr.agg_reports[one] = reg_report_buffer.read(one);
                hdr.agg_reports[two] = reg_report_buffer.read(two);
                hdr.agg_reports[three] = reg_report_buffer.read(three);
                hdr.agg_reports[four] = reg_report_buffer.read(four);
                hdr.agg_reports[five] = reg_report_buffer.read(five);
                hdr.agg_reports[six] = reg_report_buffer.read(six);
                hdr.agg_reports[seven] = reg_report_buffer.read(seven);
                hdr.agg_reports[eight] = reg_report_buffer.read(eight);
                hdr.agg_reports[nine] = reg_report_buffer.read(nine);
                hdr.agg_reports[ten] = reg_report_buffer.read(ten);
                hdr.agg_reports[eleven] = reg_report_buffer.read(eleven);
                hdr.agg_reports[twelve] = reg_report_buffer.read(twelve);
                hdr.agg_reports[thirteen] = reg_report_buffer.read(thirteen);
                hdr.agg_reports[fourteen] = reg_report_buffer.read(fourteen);
                hdr.agg_reports[fifteen] = reg_report_buffer.read(fifteen);

                pointer = 0;
                reg_report_counter.write(zero, pointer);
            }
        }
    }
}


control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

control CommonDeparserImpl(packet_out packet,
                           inout headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control IngressDeparserImpl(packet_out buffer,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    CommonDeparserImpl(buffer,hdr) cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    CommonDeparserImpl(buffer,hdr) cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;