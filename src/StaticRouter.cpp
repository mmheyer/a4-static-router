#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"
#include "RoutingTable.h"
#include "ICMPSender.h"

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below
    /* static router
    receives raw ethernet frames, process packets, forward to correct outgoing interface

    */

    //extract ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t etype = ntohs(ethHeader->ether_type);

    if(etype == ethertype_arp){
        handleARP(packet, iface, ethHeader);
    } //else if(etype == ethertype_ip){
   //     handleIP(packet, iface, ethHeader);
   // } 
   else{
        spdlog::error("Unsupported EtherType: {:#06x}", etype);
    }

}

void StaticRouter::handleARP(std::vector<uint8_t> &packet, std::string &iface, sr_ethernet_hdr_t *ethHeader){
    //constexpr inline size_t ARP_PACKET_SIZE = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    if(packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)){
        spdlog::error("Packet not large enough to contain ARP.");
        return; 
    }

    auto *arpHeader = reinterpret_cast<sr_arp_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t));
    unsigned short op = ntohs(arpHeader->ar_op);
    std::array<unsigned char, 6> macAddr;
    std::copy(std::begin(arpHeader->ar_sha), std::end(arpHeader->ar_sha), macAddr.begin());

    if(op == arp_op_reply){
        spdlog::info("Received ARP reply.");
        //  virtual void addEntry(uint32_t ip, const mac_addr &mac) = 0;
        arpCache->addEntry(arpHeader->ar_sip, macAddr);
        spdlog::info("ARP cache updated with IP: {:#08x}", ntohl(arpHeader->ar_sip));
    } else if(op == arp_op_request){
        spdlog::info("Received ARP Request");
        //get ip 
        //TODO FIX::: 
        auto x = routingTable->getRoutingEntry(ntohl(arpHeader->ar_tip));
        if (!x) {
            spdlog::info("No route found for the requested IP: {:#08x}. Ignoring ARP request.", ntohl(arpHeader->ar_tip));
            return;
        }
        RoutingEntry routerIp = *x;
        


        spdlog::info("This router owns the requested IP.");
        //arp reply 
        // Construct ARP reply packet
        std::vector<uint8_t> reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        auto *replyEthH = reinterpret_cast<sr_ethernet_hdr_t *>(reply.data());
        auto *replyArpH = reinterpret_cast<sr_arp_hdr_t *>(reply.data() + sizeof(sr_ethernet_hdr_t));

        std::memcpy(replyEthH->ether_dhost, ethHeader->ether_shost, ETHER_ADDR_LEN); // Target (source of the request)
        //TODO FIXXX
        RoutingInterface RI = routingTable->getRoutingInterface(iface);                 // Source(router's MAC for the interface)
        std::memcpy(replyEthH->ether_shost, RI.mac.data(), ETHER_ADDR_LEN); // (router's MAC)

        replyEthH->ether_type = htons(ethertype_arp);

        replyArpH->ar_op = htons(arp_op_reply);
        replyArpH->ar_hrd = htons(arp_hrd_ethernet); 
        replyArpH->ar_pro = htons(ethertype_ip);
        replyArpH->ar_hln = ETHER_ADDR_LEN;
        replyArpH->ar_pln = sizeof(in_addr);
        std::memcpy(replyArpH->ar_sha, replyEthH->ether_shost, ETHER_ADDR_LEN);
        replyArpH->ar_sip = htonl(routerIp.dest); 
        std::memcpy(replyArpH->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
        replyArpH->ar_tip = arpHeader->ar_sip; 

        // Send ARP reply
        packetSender->sendPacket(reply, iface);
        spdlog::info("ARP reply sent to IP: {:#08x}", ntohl(arpHeader->ar_sip));

    } else{
         spdlog::error("Unsupported ARP Op: {:#06x}", ntohs(arpHeader->ar_op));
    }
}

void StaticRouter::handleIP(std::vector<uint8_t>& packet, const std::string& iface, sr_ethernet_hdr_t* ethHeader) {
    // Check if packet contains an IP header
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        spdlog::error("Packet is too small to contain an IP header.");
        return;
    }

    // Extract IP header
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    // Verify checksum
    uint16_t originalChecksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    if (cksum(ipHeader, sizeof(sr_ip_hdr_t)) != originalChecksum) {
        spdlog::error("Invalid IP checksum. Dropping packet.");
        return;
    }

    // Check if the destination IP matches one of the router's interfaces
    for (const auto& [ifaceName, ifaceInfo] : routingTable->getRoutingInterfaces()) {
        if (ifaceInfo.ip == ntohl(ipHeader->ip_dst)) {
            if (ipHeader->ip_p == ip_protocol_icmp) {
                // Handle ICMP Echo Request
                handleICMPEchoRequest(packet, iface, ethHeader);
            } else {
                // Send ICMP Port Unreachable
                icmpSender->sendDestinationUnreachable(packet, iface, ifaceInfo.ip, 3 /* Port Unreachable */);
            }
            return;
        }
    }

    // Forward the packet
    forwardIPPacket(packet, iface, ethHeader, ipHeader);
}

void StaticRouter::forwardIPPacket(std::vector<uint8_t>& packet, const std::string& iface,
                                   sr_ethernet_hdr_t* ethHeader, sr_ip_hdr_t* ipHeader) {
    // Decrement TTL and recompute checksum
    ipHeader->ip_ttl--;
    if (ipHeader->ip_ttl == 0) {
        icmpSender->sendTimeExceeded(packet, iface, ntohl(ipHeader->ip_src));
        return;
    }
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // Lookup routing table
    auto route = routingTable->getRoutingEntry(ntohl(ipHeader->ip_dst));
    if (!route) {
        icmpSender->sendDestinationUnreachable(packet, iface, ntohl(ipHeader->ip_src), 0 /* Network Unreachable */);
        return;
    }

    // Check ARP cache for next-hop MAC
    auto nextHopMAC = arpCache->getEntry(route->gateway);
    if (nextHopMAC) {
        // Update Ethernet header with next-hop MAC and router's MAC
        std::memcpy(ethHeader->ether_dhost, nextHopMAC->data(), ETHER_ADDR_LEN);
        std::memcpy(ethHeader->ether_shost, routingTable->getRoutingInterface(route->iface).mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(packet, route->iface);
    } else {
        // Queue the packet and send ARP request
        arpCache->queuePacket(route->gateway, packet, route->iface);
        arpSender->sendArpRequest(route->gateway, routingTable->getRoutingInterface(route->iface).ip,
                                  routingTable->getRoutingInterface(route->iface).mac.data(), route->iface);
    }
}

void StaticRouter::handleICMPEchoRequest(std::vector<uint8_t>& packet, const std::string& iface,
                                         sr_ethernet_hdr_t* ethHeader) {
    // Extract ICMP header and validate
    auto* icmpHeader = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    if (icmpHeader->icmp_type != 8 /* Echo Request */) {
        spdlog::error("Unsupported ICMP type. Dropping packet.");
        return;
    }

    // Construct and send ICMP Echo Reply
    icmpSender->sendICMPEchoReply(packet, iface, ntohl(reinterpret_cast<sr_ip_hdr_t*>(ethHeader + 1)->ip_src));
}
