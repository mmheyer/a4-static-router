#ifndef ARPSENDER_H
#define ARPSENDER_H

#include "IPacketSender.h"
#include "protocol.h"
#include <memory>
#include <vector>
#include <string>
#include <cstring>
#include "ICMPSender.h"


/**
 * @brief Handles sending ARP messages.
 */
class ARPSender {
public:
    /**
     * @brief Constructor for ARPSender.
     * @param packetSender Shared pointer to the IPacketSender.
     */
    explicit ARPSender(std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Sends an ARP request to resolve an IP address.
     * @param targetIP The IP address to resolve.
     * @param senderIP The IP address of the sender.
     * @param senderMac The MAC address of the sender.
     * @param iface The interface to send the ARP request on.
     */
    void sendArpRequest(uint32_t targetIP, uint32_t senderIP, const uint8_t senderMac[6], const std::string& iface);

    /**
     * @brief Sends an ARP reply.
     * @param targetIP The target's IP address.
     * @param targetMac The target's MAC address.
     * @param senderIP The sender's IP address.
     * @param senderMac The sender's MAC address.
     * @param iface The interface to send the ARP reply on.
     */
    void sendArpReply(uint32_t targetIP, const uint8_t targetMac[6], uint32_t senderIP, const uint8_t senderMac[6], const std::string& iface);

private:
    std::shared_ptr<IPacketSender> packetSender_;
};

#endif // ARPSENDER_H