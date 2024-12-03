#include <iostream>

#include "detail/BridgeClient.h"
#include "detail/cxxopts.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

void initializeLogging() {
    try {
        // Create a rotating file logger
        auto logger = spdlog::rotating_logger_mt(
            "arp_logger", "logs/arp_cache.log", 1048576 * 5, 3); // 5MB log file, 3 rotations
        logger->set_level(spdlog::level::info);                  // Set log level to info
        logger->flush_on(spdlog::level::info);                   // Flush on info level
        spdlog::set_default_logger(logger);                      // Set as the default logger
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
    }
}

int main(int argc, char **argv)
{
    cxxopts::Options options("StaticRouter", "Static Router for EECS 489 P4");
    options.add_options()
        ("h,help", "Print help")
        ("r,routing-table", "Path to routing table", cxxopts::value<std::string>()->default_value("rtable"))
        ("p,pcap-prefix", "Prefix for pcap files", cxxopts::value<std::string>()->default_value("sr_capture"));

    auto result = options.parse(argc, argv);

    // initialize logger
    initializeLogging();

    BridgeClient client(result["routing-table"].as<std::string>(), result["pcap-prefix"].as<std::string>());
    client.run();
}