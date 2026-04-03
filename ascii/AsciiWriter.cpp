#include "AsciiWriter.h"
#include <iomanip>

AsciiWriter::AsciiWriter() = default;

AsciiWriter::~AsciiWriter() {
    close();
}

bool AsciiWriter::create(const std::string& filePath) {
    outputFile_.open(filePath);
    if (!outputFile_.is_open()) {
        return false;
    }

    outputFile_ << "Timestamp,ID,DLC,Data\n";
    return true;
}

void AsciiWriter::writeFrame(const Frame& frame) {
    // Timestamp en secondes (ex: 0.001234)
    double timestampSec = static_cast<double>(frame.timestamp) / 1'000'000.0;
    outputFile_ << std::fixed << std::setprecision(6) << timestampSec << ",";
    outputFile_ << "0x" << std::hex << std::uppercase << frame.id << std::nouppercase << std::dec << ",";
    outputFile_ << static_cast<int>(frame.dlc) << ",";

    for (size_t i = 0; i < frame.data.size(); ++i) {
        outputFile_ << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                    << static_cast<int>(frame.data[i]) << std::nouppercase;
        if (i < frame.data.size() - 1) {
            outputFile_ << " ";
        }
    }

    outputFile_ << std::dec << "\n";
}

void AsciiWriter::close() {
    if (outputFile_.is_open()) {
        outputFile_.close();
    }
}
