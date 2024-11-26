#include "ARPSender.h"
#include "IPacketSender.h"

class ARPSenderImpl : public ARPSender {
private:
    std::shared_ptr<IPacketSender> packetSender;

public:
    explicit ARPSenderImpl(std::shared_ptr<IPacketSender> packetSender)
        : packetSender(std::move(packetSender)) {}

    void sendARPRequest(uint32_t targetIp, uint32_t senderIp, const uint8_t* senderMac,
                        const std::string& iface) override {
        // Construct ARP request packet (omitted for brevity)
        Packet arpRequest = constructARPRequest(targetIp, senderIp, senderMac);
        packetSender->sendPacket(arpRequest, iface);
    }

    void sendARPReply(uint32_t targetIp, const uint8_t* targetMac, uint32_t senderIp,
                      const uint8_t* senderMac, const std::string& iface) override {
        // Construct ARP reply packet (omitted for brevity)
        Packet arpReply = constructARPReply(targetIp, targetMac, senderIp, senderMac);
        packetSender->sendPacket(arpReply, iface);
    }

private:
    Packet constructARPRequest(uint32_t targetIp, uint32_t senderIp, const uint8_t* senderMac) {
        // Build ARP request packet
        Packet packet;
        // Fill packet data...
        return packet;
    }

    Packet constructARPReply(uint32_t targetIp, const uint8_t* targetMac, uint32_t senderIp,
                             const uint8_t* senderMac) {
        // Build ARP reply packet
        Packet packet;
        // Fill packet data...
        return packet;
    }
};