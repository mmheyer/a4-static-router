#ifndef ICMPMESSAGE_H
#define ICMPMESSAGE_H

#include <vector>
#include <string>
#include <cstring>
#include "protocol.h"
#include "IPacketSender.h"

class ICMPMessage {
private:
    enum Type {
        echo_reply = 0,
        destination_unreachable = 3,
        time_exceeded = 11
    };
public:
    ICMPMessage(std::shared_ptr<IPacketSender>, const std::string& iface)
        : packetSender(packetSender), iface(iface) {}

    void sendEchoReply(uint32_t srcIp, uint32_t dstIp, const uint8_t* data, size_t dataSize);
    void sendDestinationUnreachable(uint32_t srcIp, uint32_t dstIp, const Packet& originalPacket, uint8_t icmpCode);
    void sendTimeExceeded(uint32_t srcIp, uint32_t dstIp, const uint8_t* data, size_t dataSize);
    void sendPortUnreachable(uint32_t srcIp, uint32_t dstIp, const uint8_t* data, size_t dataSize);

private:
    std::shared_ptr<IPacketSender> packetSender;
    std::string iface;

    void sendMessage(uint32_t srcIp, uint32_t dstIp, const uint8_t* payload, size_t payloadSize, uint8_t protocol);
    void wrapInIPHeader(std::vector<uint8_t>& packet, uint32_t srcIp, uint32_t dstIp, uint8_t protocol);
};

#endif // ICMPMESSAGE_H