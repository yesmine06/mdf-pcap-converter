#pragma once

#include "../bus/BusTypes.h"
#include <string>
#include <vector>
#include <fstream>

/**
 * PcapNgWriter - Ecrit des trames multi-bus au format PCAPNG.
 * Format: SHB + IDB + EPB (Enhanced Packet Blocks).
 */
class PcapNgWriter {
public:
    PcapNgWriter();
    ~PcapNgWriter();

    bool open(const std::string& filePath, BusType busType = BusType::CAN);
    void writeFrame(const Frame& frame);
    void close();

private:
    void writeBlockType(uint32_t type);
    void writeBlockLength(uint32_t len);
    std::vector<uint8_t> buildPacketData(const Frame& frame);

    std::ofstream* file_ = nullptr;
    BusType busType_ = BusType::CAN;
};
