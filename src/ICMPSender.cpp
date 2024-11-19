#include "ICMPSender.h"
#include "utils.h"

ICMPSender::ICMPSender(uint32_t routerIp, const uint8_t* routerMac)
    : routerIp_(routerIp) {
    std::copy(routerMac, routerMac + ETHER_ADDR_LEN, routerMac_);
}

void ICMPSender::sendIcmpDestinationHostUnreachable(const std::string& iface, const sr_ip_hdr_t& ipHdr, const uint8_t* destMac) {
    // Create an ICMP type 3 message (Destination Host Unreachable).
    sr_icmp_t3_hdr_t icmpHdr = {};
    icmpHdr.icmp_type = ICMP_TYPE_TIME_EXCEEDED; // Type 3
    icmpHdr.icmp_code = ICMP_CODE_DEST_HOST_UNREACHABLE; // Code 1
    icmpHdr.icmp_sum = 0; // Set later after computing checksum

    // Copy original IP header and payload into ICMP data
    std::memcpy(icmpHdr.data, &ipHdr, ICMP_DATA_SIZE);

    // Compute checksum
    icmpHdr.icmp_sum = cksum(reinterpret_cast<uint16_t*>(&icmpHdr), sizeof(icmpHdr));

    // Construct IP header
    sr_ip_hdr_t ipHdrReply = {};
    // ipHdrReply.ip_v = 4; // IPv4
    // ipHdrReply.ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ipHdrReply.ip_tos = 0;
    ipHdrReply.ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ipHdrReply.ip_id = 0;
    ipHdrReply.ip_off = 0;
    ipHdrReply.ip_ttl = 64;
    ipHdrReply.ip_p = ip_protocol_icmp; // ICMP protocol
    ipHdrReply.ip_src = routerIp_;
    ipHdrReply.ip_dst = ipHdr.ip_src; // Destination is the source of the triggering packet
    ipHdrReply.ip_sum = 0; // Set later after computing checksum
    ipHdrReply.ip_sum = cksum(reinterpret_cast<uint16_t*>(&ipHdrReply), sizeof(ipHdrReply));

    // Construct Ethernet header
    sr_ethernet_hdr_t ethHdr = {};
    std::copy(destMac, destMac + ETHER_ADDR_LEN, ethHdr.ether_dhost); // Destination MAC
    std::copy(routerMac_, routerMac_ + ETHER_ADDR_LEN, ethHdr.ether_shost); // Source MAC
    ethHdr.ether_type = htons(ethertype_ip);

    // Combine all headers and send
    Packet packet(sizeof(sr_ethernet_hdr_t) + ntohs(ipHdrReply.ip_len));
    std::memcpy(packet.data(), &ethHdr, sizeof(sr_ethernet_hdr_t));
    std::memcpy(packet.data() + sizeof(sr_ethernet_hdr_t), &ipHdrReply, sizeof(sr_ip_hdr_t));
    std::memcpy(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmpHdr, sizeof(sr_icmp_t3_hdr_t));

    sendPacket(packet, iface);
}
