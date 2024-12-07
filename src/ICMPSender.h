#ifndef ICMPSENDER_H
#define ICMPSENDER_H

#include "IPacketSender.h"
#include "protocol.h"
#include <memory>
#include <vector>
#include <string>
#include <cstdint>

class ICMPSender {
public:
    enum class DestinationUnreachableCode {
        NET_UNREACHABLE = 0,
        HOST_UNREACHABLE = 1,
        PORT_UNREACHABLE = 3,
    };

    explicit ICMPSender(std::shared_ptr<IPacketSender> packetSender);

    // /**
    //  * @brief Sends an ICMP Echo Reply.
    //  * @param requestPacket The original Echo Request packet.
    //  * @param sourceMAC The source MAC address for the Ethernet header.
    //  * @param sourceIP The source IP address for the reply.
    //  * @param iface The interface on which to send the reply.
    //  */
    // void sendEchoReply(const std::vector<uint8_t>& requestPacket,
    //                    const mac_addr& sourceMAC,
    //                    uint32_t sourceIP,
    //                    const std::string& iface);

    /**
     * @brief Sends an ICMP Destination Unreachable message.
     * @param originalPacket The original packet causing the error.
     * @param sourceMAC The source MAC address for the Ethernet header.
     * @param sourceIP The source IP address for the ICMP message.
     * @param destMAC The destination MAC address for the Ethernet header.
     * @param destIP The destination IP address for the ICMP message.
     * @param iface The interface on which to send the message.
     * @param code The specific code for the Destination Unreachable message.
     */
    void sendDestinationUnreachable(const std::vector<uint8_t>& originalPacket,
                                            const mac_addr& sourceMAC,
                                            uint32_t sourceIP,
                                            const mac_addr& destMAC,
                                            uint32_t destIP,
                                            const std::string& iface,
                                            uint8_t icmpCode);

    /**
     * @brief Sends an ICMP Time Exceeded message.
     * @param originalPacket The original packet causing the error.
     * @param sourceMAC The source MAC address for the Ethernet header.
     * @param sourceIP The source IP address for the ICMP message.
     * @param destMAC The destination MAC address for the Ethernet header.
     * @param destIP The destination IP address for the ICMP message.
     * @param iface The interface on which to send the message.
     */
    void sendTimeExceeded(const std::vector<uint8_t>& originalPacket,
                          const mac_addr& sourceMAC,
                          uint32_t sourceIP,
                          const mac_addr& destMAC,
                          uint32_t destIP,
                          const std::string& iface);

    /**
     * @brief Sends an ICMP Port Unreachable message.
     * @param originalPacket The original packet causing the error.
     * @param sourceMAC The source MAC address for the Ethernet header.
     * @param sourceIP The source IP address for the ICMP message.
     * @param destMAC The destination MAC address for the Ethernet header.
     * @param destIP The destination IP address for the ICMP message.
     * @param iface The interface on which to send the message.
     */
    void sendPortUnreachable(const std::vector<uint8_t>& originalPacket,
                             const mac_addr& sourceMAC,
                             uint32_t sourceIP,
                             const mac_addr& destMAC,
                             uint32_t destIP,
                             const std::string& iface);

private:
    std::shared_ptr<IPacketSender> packetSender_;

    /**
     * @brief Constructs a full ICMP packet with Ethernet, IP, and ICMP headers.
     * @param originalPacket The original packet causing the error.
     * @param sourceIP The source IP address for the ICMP message.
     * @param destIP The destination IP address for the ICMP message.
     * @param sourceMAC The source MAC address for the Ethernet header.
     * @param destMAC The destination MAC address for the Ethernet header.
     * @param icmpType The ICMP message type.
     * @param icmpCode The ICMP message code.
     * @return A complete Ethernet frame containing the ICMP message.
     */
    std::vector<uint8_t> constructICMPPacket(const std::vector<uint8_t>& originalPacket,
                                             uint32_t sourceIP,
                                             uint32_t destIP,
                                             const mac_addr& sourceMAC,
                                             const mac_addr& destMAC,
                                             uint8_t icmpType,
                                             uint8_t icmpCode);
};

#endif // ICMPSENDER_H