/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// 定义常量
const bit<16> TYPE_IPV4 = 0x0800;         // IPv4 以太网类型
const bit<16> TYPE_IPV6 = 0x86DD;         // IPv6 以太网类型

//工业控制协议 以太网类型
//A类-准RT
//const bit<16> TYPE_ETHERNET_IP = 0x88B5;     // EtherNet/IP
//const bit<16> TYPE_MODBUS_TCP = 0x88B6;      // Modbus TCP/UDP
//const bit<16> TYPE_EAP = 0x88A4;             // EtherCAT Automation Protocol (EAP)

//B类-RT
const bit<16> TYPE_PROFINET_RT = 0x8892;       // ProfiNET (RT)
//const bit<16> TYPE_POWER_LINK = 0x88AB;      // Power Link

//C类-IRT
//const bit<16> TYPE_PROFINET_IRT = 0x88F7;    // ProfiNET (IRT)
//const bit<16> TYPE_CC_LINK_IE = 0x890F;      // CC-Link IE
//const bit<16> TYPE_SERCOS_III = 0x88CD;      // Sercos III
//const bit<16> TYPE_ETHERCAT = 0x88A4;        // EtherCAT


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// 新的以太网头部，用于存储映射后的MAC地址
header new_ethernet_t{
    macAddr_t new_dstAddr;  // 新的目的MAC地址
    macAddr_t new_srcAddr;  // 新的源MAC地址
    bit<16>   etherType;    // 以太网类型
}

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

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNom;
    bit<32> ackNom;
    bit<4>  dataOffset;
    bit<4>  flags;
    bit<16> windowSize;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header modbusTCP_t {
    bit<16> transactionId;
    bit<16> protocolId;
    bit<16> length;
    bit<8> unitId;
    bit<8> functionCode;
}

header profinetRT_t {
    bit<4>  frameID;
    bit<4>  frameType;
    bit<16> datalength;
    bit<8>  telegramNumber;
}

struct metadata {
    bit<1> is_modbus;    // 是否为Modbus TCP数据包的标记
    bit<1> is_profinet;  // 是否为Profinet数据包的标记
}


struct headers {
    new_ethernet_t  new_ethernet;
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    ipv6_t          ipv6;
    tcp_t           tcp;
    modbusTCP_t     modbus;
    profinetRT_t    profinet;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        // 提取以太网头部
        packet.extract(hdr.ethernet);  
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: ipv4;             // 如果是IPv4类型，转到解析IPv4状态    
            TYPE_IPV6: ipv6;             // 如果是IPv6类型，转到解析IPv6状态
            TYPE_PROFINET_RT: profinet;  // 如果是Profinet类型，转到解析Profinet状态
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x06: tcp;     // 如果协议是TCP，转到解析TCP状态
            default: accept;
        }
    }

    state ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) {
            0x06: tcp;     // 如果协议是TCP，转到解析TCP状态
            default: accept;
        }
    }

    state tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
            5020: modbusTCP;  // 如果目的端口是502，转到Modbus处理状态
            default: accept;
        }
    }

    state modbusTCP {
        meta.is_modbus = 1;  // 设置Modbus标记
        transition accept;   // 接受数据包
    }

    state profinet {
        packet.extract(hdr.profinet);  
        meta.is_profinet = 1;   // 设置Profinet标记
        transition accept;      // 接受数据包
    }
}



/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {  
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // 基于简单哈希的映射，将原始以太网头的MAC地址映射到新的以太网头
    action map_addresses(macAddr_t srcAddr, macAddr_t dstAddr) {
        bit<48> hash_src = (srcAddr ^ 0x123456789ABC) & 0xFFFFFFFFFFFF;  // 使用异或运算生成新的源MAC地址
        bit<48> hash_dst = (dstAddr ^ 0xABCDEF123456) & 0xFFFFFFFFFFFF;  // 使用异或运算生成新的目的MAC地址
        hdr.new_ethernet.new_srcAddr = hash_src;
        hdr.new_ethernet.new_dstAddr = hash_dst;
        hdr.new_ethernet.etherType = hdr.ethernet.etherType;
    }

    // 丢弃数据包动作
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // IPv4 转发动作
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    // 普通转发动作
    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    // IPv4 长度匹配表
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
        default_action = NoAction();
    }

    apply {
        // 对所有数据包应用地址映射动作
        map_addresses(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);

        if (meta.is_modbus == 1) {
            // 如果是Modbus TCP数据包，应用IPv4转发表
            ipv4_lpm.apply();
        } else if (meta.is_profinet ==1) {
            // 如果是Profinet数据包，直接转发到Profinet端口
            forward(1);     // 假设端口1为Profinet处理端口
        } else if (hdr.ipv4.isValid()) {
            // 对于有效的IPv4数据包，应用IPv4查找表
            ipv4_lpm.apply();
        } else {
            // 对于其他不符合条件的数据包，丢弃
            drop();
        }
        
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {update_checksum(
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
        packet.emit(hdr.new_ethernet);  // 输出新的以太网头部
        packet.emit(hdr.ethernet);      // 输出原始以太网头部
        packet.emit(hdr.ipv4);          // 输出 IPv4 头部
        packet.emit(hdr.tcp);           // 输出 TCP 头部
        packet.emit(hdr.modbus);        // 输出 Modbus TCP 头部
        packet.emit(hdr.profinet);      // 输出 profinet RT 头部
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
