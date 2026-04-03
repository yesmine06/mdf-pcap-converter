#pragma once

#include <string>

class ConversionManager {
public:
    bool mdfToAscii(const std::string& input, const std::string& output);
    bool mdfToPcap(const std::string& input, const std::string& output);
    bool mdfToPcapng(const std::string& input, const std::string& output);
    bool asciiToPcap(const std::string& input, const std::string& output);
    bool asciiToPcapng(const std::string& input, const std::string& output);
    bool pcapToMdf(const std::string& input, const std::string& output);
    bool pcapToPcapng(const std::string& input, const std::string& output);
    bool pcapngToPcap(const std::string& input, const std::string& output);
    bool pcapngToMdf(const std::string& input, const std::string& output);

    /** Verifies MDF->PCAP conformity: converts, then compares frame count and sample content. */
    bool verifyMdfToPcap(const std::string& mdfPath, const std::string& pcapPath, size_t sampleSize = 5);

    /** Verifies PCAP->MDF conformity: converts PCAP to MDF, then MDF to ASCII, compares frame count and sample (ID, DLC, Data). */
    bool verifyPcapToMdf(const std::string& pcapPath, const std::string& mdfPath, size_t sampleSize = 5);
};
