#pragma once

#include "../bus/BusTypes.h"
#include <string>
#include <vector>
#include <fstream>

/**
 * PcapReader - Lit des trames au format PCAP.
 * Supporte DLT 227 (CAN SocketCAN) et DLT 254 (LIN).
 */
class PcapReader {
public:
    PcapReader();
    ~PcapReader();

    bool open(const std::string& filePath);
    bool readFrame(Frame& frame);
    void close();

    /** Extrait toutes les trames supportees (CAN/LIN) dans un vecteur. */
    bool extractFrames(std::vector<Frame>& out);

private:
    std::ifstream* file_ = nullptr;
    uint32_t dlt_ = 0;  // Data Link Type
    bool bigEndian_ = false;  // Fichier ecrit par machine big-endian
    bool usecResolution_ = true;  // true=µs (0xa1b2c3d4), false=ns (0xa1b23c4d)
};
