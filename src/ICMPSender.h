#ifndef ICMPSENDER_H
#define ICMPSENDER_H

#include "IPacketSender.h"
#include "protocol.h" // For packet structure definitions
#include <memory>
#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Handles sending ICMP messages.
 */
class ICMPSender {
public:
    enum class DestinationUnreachableCode {
        NETWORK_UNREACHABLE = 0, // Network Unreachable (Code 0)
        HOST_UNREACHABLE = 1,    // Host Unreachable (Code 1)
        // PROTOCOL_UNREACHABLE = 2,// Protocol Unreachable (Code 2)
        PORT_UNREACHABLE = 3,    // Port Unreachable (Code 3)
        // FRAGMENTATION_NEEDED = 4 // Fragmentation Needed (Code 4)
    };

    /**
     * @brief Constructor for ICMPSender.
     * @param packetSender Shared pointer to the IPacketSender.
     */
    explicit ICMPSender(std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Sends a destination unreachable message.
     * @param packet The original packet causing the error.
     * @param iface The interface on which the message is sent.
     * @param sourceIP The IP address to use as the source in the ICMP message.
     * @param icmpCode The ICMP code indicating the specific error (e.g., network unreachable, host unreachable).
     */
    void sendDestinationUnreachable(const std::vector<uint8_t>& packet,
                                    const std::string& iface,
                                    uint32_t sourceIP,
                                    uint8_t icmpCode);

    /**
     * @brief Sends a time exceeded message.
     * @param packet The original packet causing the error.
     * @param iface The interface on which the message is sent.
     * @param sourceIP The IP address to use as the source in the ICMP message.
     */
    void sendTimeExceeded(const std::vector<uint8_t>& packet,
                          const std::string& iface,
                          uint32_t sourceIP);

private:
    std::shared_ptr<IPacketSender> packetSender_;

    /**
     * @brief Constructs the ICMP message for the given parameters.
     * @param originalPacket The original packet causing the error.
     * @param sourceIP The source IP address for the ICMP message.
     * @param destIP The destination IP address for the ICMP message.
     * @param icmpType The type of the ICMP message.
     * @param icmpCode The code of the ICMP message.
     * @return A complete ICMP message wrapped in an IP header as a vector of bytes.
     */
    std::vector<uint8_t> constructICMPMessage(const std::vector<uint8_t>& originalPacket,
                                              uint32_t sourceIP,
                                              uint32_t destIP,
                                              uint8_t icmpType,
                                              uint8_t icmpCode);
};

#endif // ICMPSENDER_H
