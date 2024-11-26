#include "ICMPSender.h"

void ICMPSender::sendICMPMessage(uint32_t sourceIp, uint32_t destinationIp, const Packet& originalPacket,
                        uint8_t icmpType, uint8_t icmpCode, const std::string& iface) override {
    ICMPMessage icmpMessage(packetSender, iface);
    Packet icmpPacket = icmpMessage.createMessage(sourceIp, destinationIp, originalPacket, icmpType, icmpCode);
    packetSender->sendPacket(icmpPacket, iface);
}