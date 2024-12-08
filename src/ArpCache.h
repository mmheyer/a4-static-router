#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <vector>
#include <array>
#include <chrono>
#include <set>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>
#include <cstring>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"
#include "ICMPSender.h"
// #include "ARPSender.h"

class ArpCache : public IArpCache {
public:
    ArpCache(std::chrono::milliseconds timeout,
        std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache() override;

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac) override;

    std::optional<mac_addr> getEntry(uint32_t ip) override;

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) override;

    bool hasRequest(uint32_t senderIp);
    std::optional<std::__cxx11::list<AwaitingPacket>> getQueuedPackets(uint32_t ip);
private:
    void loop();

    std::chrono::milliseconds timeout;

    std::mutex mutex;
    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
    std::unordered_map<ip_addr, ArpRequest> requests;

    std::shared_ptr<ICMPSender> icmpSender;
    // std::shared_ptr<ARPSender> arpSender;

    void processRequest(ArpRequest& req);
    void sendArpRequest(uint32_t targetIP, uint32_t senderIP, const uint8_t senderMac[6], const std::string& iface);
};

#endif //ARPCACHE_H