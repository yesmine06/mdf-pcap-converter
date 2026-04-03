#pragma once

#include "../bus/BusTypes.h"
#include <string>
#include <vector>

/**
 * MdfFrameWriter - Ecrit des trames CAN/LIN en fichier MDF via mdflib.
 * Utilise MdfBusLogger pour le format bus logger ASAM.
 */
class MdfFrameWriter {
public:
    MdfFrameWriter();
    ~MdfFrameWriter();

    bool open(const std::string& filePath, BusType busType = BusType::CAN, size_t maxPayload = 64);
    bool writeFrames(const std::vector<Frame>& frames);
    void close();

private:
    void* writer_ = nullptr;  // mdf::MdfWriter* (opaque)
    std::string filePath_;
};
