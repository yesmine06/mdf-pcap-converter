#pragma once

#include "../bus/BusTypes.h"
#include <string>
#include <fstream>

/**
 * PcapWriter - Ecrit des trames multi-bus au format PCAP.
 * DLT par type: CAN=227, LIN=254, FlexRay=259, Ethernet=1.
 */
class PcapWriter {
public:
    PcapWriter();
    ~PcapWriter();

    bool open(const std::string& filePath, BusType busType = BusType::CAN, bool useNanoseconds = false);
    void writeFrame(const Frame& frame);
    void close();

private:
    std::ofstream* file_ = nullptr;
    BusType busType_ = BusType::CAN;
    bool useNanoseconds_ = false;
};
