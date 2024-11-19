#ifndef ICMPSENDER_H
#define ICMPSENDER_H

#include "IPacketSender.h"
#include "protocol.h"

class ICMPSender : public IPacketSender {
public:
    // Constructor that accepts the router's own IP and MAC address
    ICMPSender(uint32_t routerIp, const uint8_t* routerMac);

    /**
     * @brief Sends an ICMP Destination Host Unreachable message.
     * @param iface The outgoing interface.
     * @param ipHdr The original IP header that triggered the ICMP message.
     * @param destMac The destination MAC address.
     */
    void sendIcmpDestinationHostUnreachable(const std::string& iface, const sr_ip_hdr_t& ipHdr, const uint8_t* destMac);

private:
    uint32_t routerIp_;
    uint8_t routerMac_[ETHER_ADDR_LEN];
};

#endif //ICMPSENDER_H