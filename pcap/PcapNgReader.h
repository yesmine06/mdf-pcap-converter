#pragma once

#include "../bus/BusTypes.h"
#include <string>
#include <vector>
#include <map>
#include <fstream>

/**
 * PcapNgReader - Lit des trames au format PCAPNG.
 * Supporte blocs SHB, IDB, EPB. DLT 227 (CAN), 254 (LIN), 259 (FlexRay), 1 (Ethernet).
 * Gere plusieurs interfaces : chaque EPB utilise le DLT de son interface_id.
 */
class PcapNgReader {
public:
    PcapNgReader();
    ~PcapNgReader();

    bool open(const std::string& filePath);
    bool readFrame(Frame& frame);
    void close();

    bool extractFrames(std::vector<Frame>& out);

private:
    bool readNextBlock();
    bool parseEpb(const uint8_t* data, size_t len, uint32_t dlt);

    std::ifstream* file_ = nullptr;
    std::map<uint32_t, uint32_t> interfaceToDlt_;
    uint32_t nextInterfaceId_ = 0;
    std::vector<Frame> frameQueue_;
    size_t queueIdx_ = 0;
};
