#include "ConversionManager.h"
#include "mdf/MdfReaderWrapper.h"
#include "mdf/MdfFrameWriter.h"
#include "ascii/AsciiReader.h"
#include "pcap/PcapWriter.h"
#include "pcap/PcapNgWriter.h"
#include "pcap/PcapReader.h"
#include "pcap/PcapNgReader.h"
#include "bus/BusTypes.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

static void removeFile(const std::string& path) {
    if (std::remove(path.c_str()) != 0) {
        std::cerr << "Warning: could not remove temp file: " << path << std::endl;
    }
}

/** Aligné sur MdfReader::maxPayloadForBus : évite de partir de 8 pour FlexRay/CAN avant le max réel. */
static size_t maxPayloadHintForMdfWriter(BusType bus) {
    switch (bus) {
        case BusType::Ethernet: return 1518;
        case BusType::FlexRay: return 254;
        case BusType::CAN_FD:
        case BusType::CAN: return 64;
        case BusType::LIN:
        default: return 8;
    }
}

static void capMaxPayloadToBusLimits(BusType bus, size_t& maxPayload) {
    if (bus == BusType::Ethernet && maxPayload > 1518) maxPayload = 1518;
    else if (bus == BusType::FlexRay && maxPayload > 254) maxPayload = 254;
    else if ((bus == BusType::CAN || bus == BusType::CAN_FD) && maxPayload > 64) maxPayload = 64;
    else if (bus == BusType::LIN && maxPayload > 8) maxPayload = 8;
}

static std::string busTypeToSuffix(BusType b) {
    switch (b) {
        case BusType::CAN: return "CAN";
        case BusType::CAN_FD: return "CAN_FD";
        case BusType::LIN: return "LIN";
        case BusType::FlexRay: return "FlexRay";
        case BusType::Ethernet: return "Ethernet";
        default: return "Unknown";
    }
}

static std::string outputPathForBus(const std::string& baseOutput, const std::string& ext,
                                    BusType bus, bool multipleTypes) {
    if (!multipleTypes) return baseOutput;
    const size_t dot = baseOutput.find_last_of('.');
    const std::string stem = (dot != std::string::npos) ? baseOutput.substr(0, dot) : baseOutput;
    return stem + "_" + busTypeToSuffix(bus) + ext;
}

bool ConversionManager::mdfToAscii(const std::string& input, const std::string& output) {
    MdfReader reader;

    if (!reader.open(input)) {
        std::cerr << "Error: cannot open MDF file: " << input << std::endl;
        return false;
    }

    std::cout << "Converting: " << input << std::endl;
    if (!reader.convertToAscii(output)) {
        std::cerr << "Error: conversion failed." << std::endl;
        reader.close();
        return false;
    }

    reader.close();
    std::cout << "Conversion completed." << std::endl;
    return true;
}

bool ConversionManager::mdfToPcap(const std::string& input, const std::string& output) {
    MdfReader reader;
    if (!reader.open(input)) {
        std::cerr << "Error: cannot open MDF file: " << input << std::endl;
        return false;
    }

    std::vector<Frame> allFrames;
    if (!reader.extractFrames(allFrames) || allFrames.empty()) {
        reader.close();
        std::cerr << "No bus group (CAN/LIN/FlexRay/Ethernet) convertible in the MDF file." << std::endl;
        return false;
    }
    const uint64_t startTimeNs = reader.getMeasurementStartTimeNs();
    reader.close();

    /* Timestamps MDF : relatifs (s depuis debut) ou absolus (s epoch).
       maxTs < 86400 => relatifs (aucun epoch second < 1 jour pour dates recentes).
       Si StartTime=0, fallback : heure actuelle - maxTs (derniere trame = "now"). */
    const auto maxIt = std::max_element(allFrames.begin(), allFrames.end(),
        [](const Frame& a, const Frame& b) { return a.timestampSec < b.timestampSec; });
    const double maxTs = maxIt->timestampSec;
    const bool likelyRelative = (maxTs < 86400.0);
    if (likelyRelative) {
        double offsetSec = 0.0;
        if (startTimeNs > 0) {
            offsetSec = static_cast<double>(startTimeNs) / 1e9;
        } else {
            const auto now = std::chrono::system_clock::now();
            const double epochSec = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count()) / 1e9;
            offsetSec = epochSec - maxTs;  /* derniere trame = now (fallback si StartTime absent) */
        }
        for (auto& f : allFrames) f.timestampSec += offsetSec;
    }

    std::sort(allFrames.begin(), allFrames.end(), [](const Frame& a, const Frame& b) {
        return a.timestampSec < b.timestampSec;
    });

    std::map<BusType, std::vector<Frame>> byBus;
    for (auto& f : allFrames) byBus[f.bus].push_back(std::move(f));
    const bool multipleTypes = byBus.size() > 1;

    size_t totalWritten = 0;
    for (const auto& kv : byBus) {
        const BusType bus = kv.first;
        const std::vector<Frame>& busFrames = kv.second;
        const std::string outPath = outputPathForBus(output, ".pcap", bus, multipleTypes);
        PcapWriter writer;
        if (!writer.open(outPath, bus, true)) {  /* nanosecondes pour precision MDF */
            std::cerr << "Error: cannot create PCAP file: " << outPath << std::endl;
            return false;
        }
        for (const auto& f : busFrames) writer.writeFrame(f);
        writer.close();
        totalWritten += busFrames.size();
        std::cout << "  -> " << outPath << " (" << busFrames.size() << " frame(s) " << busTypeToSuffix(bus) << ")" << std::endl;
    }
    std::cout << "MDF -> PCAP conversion completed: " << totalWritten << " frame(s) total." << std::endl;
    return true;
}

bool ConversionManager::mdfToPcapng(const std::string& input, const std::string& output) {
    MdfReader reader;
    if (!reader.open(input)) {
        std::cerr << "Error: cannot open MDF file: " << input << std::endl;
        return false;
    }

    std::vector<Frame> allFrames;
    if (!reader.extractFrames(allFrames) || allFrames.empty()) {
        reader.close();
        std::cerr << "No bus group (CAN/LIN/FlexRay/Ethernet) convertible in the MDF file." << std::endl;
        return false;
    }
    const uint64_t startTimeNs = reader.getMeasurementStartTimeNs();
    reader.close();

    /* Meme logique timestamps que mdfToPcap */
    const auto maxItNg = std::max_element(allFrames.begin(), allFrames.end(),
        [](const Frame& a, const Frame& b) { return a.timestampSec < b.timestampSec; });
    const double maxTsNg = maxItNg->timestampSec;
    const bool likelyRelativeNg = (maxTsNg < 86400.0);
    if (likelyRelativeNg) {
        double offsetSec = 0.0;
        if (startTimeNs > 0) {
            offsetSec = static_cast<double>(startTimeNs) / 1e9;
        } else {
            const auto now = std::chrono::system_clock::now();
            const double epochSec = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count()) / 1e9;
            offsetSec = epochSec - maxTsNg;
        }
        for (auto& f : allFrames) f.timestampSec += offsetSec;
    }

    std::sort(allFrames.begin(), allFrames.end(), [](const Frame& a, const Frame& b) {
        return a.timestampSec < b.timestampSec;
    });

    std::map<BusType, std::vector<Frame>> byBus;
    for (auto& f : allFrames) byBus[f.bus].push_back(std::move(f));
    const bool multipleTypes = byBus.size() > 1;

    size_t totalWritten = 0;
    for (const auto& kv : byBus) {
        const BusType bus = kv.first;
        const std::vector<Frame>& busFrames = kv.second;
        const std::string outPath = outputPathForBus(output, ".pcapng", bus, multipleTypes);
        PcapNgWriter writer;
        if (!writer.open(outPath, bus)) {
            std::cerr << "Error: cannot create PCAPNG file: " << outPath << std::endl;
            return false;
        }
        for (const auto& f : busFrames) writer.writeFrame(f);
        writer.close();
        totalWritten += busFrames.size();
        std::cout << "  -> " << outPath << " (" << busFrames.size() << " frame(s) " << busTypeToSuffix(bus) << ")" << std::endl;
    }
    std::cout << "MDF -> PCAPNG conversion completed: " << totalWritten << " frame(s) total." << std::endl;
    return true;
}

bool ConversionManager::asciiToPcap(const std::string& input, const std::string& output) {
    AsciiReader reader;
    PcapWriter writer;

    if (!reader.open(input)) {
        std::cerr << "Error: cannot open ASCII file: " << input << std::endl;
        return false;
    }

    Frame frame;
    size_t count = 0;
    bool writerOpened = false;

    while (reader.readFrame(frame)) {
        if (!writerOpened) {
            if (!writer.open(output, frame.bus)) {
                std::cerr << "Error: cannot create PCAP file: " << output << std::endl;
                reader.close();
                return false;
            }
            writerOpened = true;
        }
        writer.writeFrame(frame);
        count++;
    }

    reader.close();
    if (writerOpened) writer.close();

    std::cout << "ASCII -> PCAP conversion completed: " << count << " frame(s) written to " << output << std::endl;
    if (count == 0) {
        std::cout << "  (No bus frame found. Measurement file (signals) not convertible to PCAP.\n"
                  << "   Expected format: Timestamp, ID, DLC, Data for CAN/LIN.)" << std::endl;
    }
    return count > 0;
}

bool ConversionManager::asciiToPcapng(const std::string& input, const std::string& output) {
    AsciiReader reader;
    PcapNgWriter writer;

    if (!reader.open(input)) {
        std::cerr << "Error: cannot open ASCII file: " << input << std::endl;
        return false;
    }

    Frame frame;
    size_t count = 0;
    bool writerOpened = false;

    while (reader.readFrame(frame)) {
        if (!writerOpened) {
            if (!writer.open(output, frame.bus)) {
                std::cerr << "Error: cannot create PCAPNG file: " << output << std::endl;
                reader.close();
                return false;
            }
            writerOpened = true;
        }
        writer.writeFrame(frame);
        count++;
    }

    reader.close();
    if (writerOpened) writer.close();

    std::cout << "ASCII -> PCAPNG conversion completed: " << count << " frame(s) written to " << output << std::endl;
    if (count == 0) {
        std::cout << "  (No bus frame found. Measurement file (signals) not convertible.\n"
                  << "   Expected format: Timestamp, ID, DLC, Data for CAN/LIN.)" << std::endl;
    }
    return count > 0;
}

bool ConversionManager::pcapToMdf(const std::string& input, const std::string& output) {
    PcapReader reader;
    if (!reader.open(input)) {
        std::cerr << "Error: cannot open PCAP file: " << input << std::endl;
        return false;
    }
    std::vector<Frame> frames;
    if (!reader.extractFrames(frames)) {
        reader.close();
        std::cerr << "No frame in PCAP file." << std::endl;
        return false;
    }
    reader.close();

    std::sort(frames.begin(), frames.end(), [](const Frame& a, const Frame& b) {
        return a.timestampSec < b.timestampSec;
    });

    /* PCAP timestamps may be relative (0-based). MDF expects epoch ns.
       Si premier timestamp < 1 jour => relatifs : offset = now - first (precision ns). */
    if (!frames.empty() && frames.front().timestampSec < 86400.0) {
        const auto now = std::chrono::system_clock::now();
        const int64_t nowNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        const double epochSec = static_cast<double>(nowNs) / 1e9;
        const double offset = epochSec - frames.front().timestampSec;
        for (auto& f : frames) f.timestampSec += offset;
    }

    for (size_t i = 1; i < frames.size(); ++i) {
        if (frames[i].timestampSec <= frames[i - 1].timestampSec) {
            frames[i].timestampSec = frames[i - 1].timestampSec + 1e-3;  /* 1 ms */
        }
    }

    /* Grouper par type de bus : CAN/CAN_FD, LIN, FlexRay, Ethernet. Un fichier MDF par type. */
    std::map<BusType, std::vector<Frame>> byBus;
    for (auto& f : frames) {
        BusType key = (f.bus == BusType::CAN_FD) ? BusType::CAN : f.bus;
        byBus[key].push_back(std::move(f));
    }

    /* Garantir timestamps strictement croissants par groupe (requis par asammdf/MDF) */
    for (auto& kv : byBus) {
        auto& busFrames = kv.second;
        for (size_t i = 1; i < busFrames.size(); ++i) {
            if (busFrames[i].timestampSec <= busFrames[i - 1].timestampSec) {
                busFrames[i].timestampSec = busFrames[i - 1].timestampSec + 1e-3;  /* 1 ms */
            }
        }
    }

    const size_t dot = output.find_last_of('.');
    const std::string baseStem = (dot != std::string::npos) ? output.substr(0, dot) : output;
    const bool multipleTypes = byBus.size() > 1;

    size_t totalWritten = 0;
    for (const auto& kv : byBus) {
        const BusType bus = kv.first;
        const std::vector<Frame>& busFrames = kv.second;
        if (busFrames.empty()) continue;

        std::string outPath = outputPathForBus(output, ".mf4", bus, multipleTypes);
        size_t maxPayload = maxPayloadHintForMdfWriter(bus);
        for (const auto& f : busFrames) {
            if (f.data.size() > maxPayload) maxPayload = f.data.size();
        }
        capMaxPayloadToBusLimits(bus, maxPayload);

        MdfFrameWriter writer;
        if (!writer.open(outPath, bus, maxPayload)) {
            std::cerr << "Error: cannot create MDF file: " << outPath << std::endl;
            return false;
        }
        if (!writer.writeFrames(busFrames)) {
            std::cerr << "Error: frame write failed for " << outPath << std::endl;
            writer.close();
            return false;
        }
        writer.close();
        totalWritten += busFrames.size();
        std::cout << "  -> " << outPath << " (" << busFrames.size() << " frame(s) " << busTypeToSuffix(bus) << ")" << std::endl;

        /* Verification: relire le MDF pour confirmer que les donnees sont presentes */
        MdfReader verifyReader;
        if (verifyReader.open(outPath)) {
            std::vector<std::pair<std::string, std::string>> cgInfo;
            verifyReader.listChannelGroupInfo(cgInfo);
            std::vector<Frame> verifyFrames;
            verifyReader.extractFrames(verifyFrames);
            verifyReader.close();
            if (verifyFrames.size() != busFrames.size()) {
                std::cerr << "  Warning: MDF verification failed - wrote " << busFrames.size()
                          << " frames but read back " << verifyFrames.size() << std::endl;
                for (const auto& p : cgInfo) {
                    std::cerr << "    CG: " << p.first << " | " << p.second << std::endl;
                }
                std::ifstream szCheck(outPath, std::ios::binary | std::ios::ate);
                if (szCheck) {
                    std::cerr << "  File size: " << szCheck.tellg() << " bytes" << std::endl;
                }
            }
        }
    }

    std::cout << "PCAP -> MDF conversion completed: " << totalWritten << " frame(s) total." << std::endl;
    return totalWritten > 0;
}

bool ConversionManager::pcapToPcapng(const std::string& input, const std::string& output) {
    PcapReader reader;
    if (!reader.open(input)) {
        std::cerr << "Error: cannot open PCAP file: " << input << std::endl;
        return false;
    }
    std::vector<Frame> frames;
    if (!reader.extractFrames(frames)) {
        reader.close();
        std::cerr << "No frame in PCAP file." << std::endl;
        return false;
    }
    reader.close();

    if (frames.empty()) return false;
    BusType bus = frames.front().bus;
    PcapNgWriter writer;
    if (!writer.open(output, bus)) {
        std::cerr << "Error: cannot create PCAPNG file: " << output << std::endl;
        return false;
    }
    for (const auto& f : frames) writer.writeFrame(f);
    writer.close();
    std::cout << "PCAP -> PCAPNG conversion completed: " << frames.size() << " frame(s) in " << output << std::endl;
    return true;
}

bool ConversionManager::pcapngToPcap(const std::string& input, const std::string& output) {
    PcapNgReader reader;
    if (!reader.open(input)) {
        std::cerr << "Error: cannot open PCAPNG file: " << input << std::endl;
        return false;
    }
    std::vector<Frame> frames;
    if (!reader.extractFrames(frames)) {
        reader.close();
        std::cerr << "No frame in PCAPNG file." << std::endl;
        return false;
    }
    reader.close();
    if (frames.empty()) return false;

    BusType bus = frames.front().bus;
    PcapWriter writer;
    if (!writer.open(output, bus, true)) {  /* nanosecondes : PCAPNG a precision ns */
        std::cerr << "Error: cannot create PCAP file: " << output << std::endl;
        return false;
    }
    for (const auto& f : frames) writer.writeFrame(f);
    writer.close();
    std::cout << "PCAPNG -> PCAP conversion completed: " << frames.size() << " frame(s) in " << output << std::endl;
    return true;
}

bool ConversionManager::pcapngToMdf(const std::string& input, const std::string& output) {
    PcapNgReader reader;
    if (!reader.open(input)) {
        std::cerr << "Error: cannot open PCAPNG file: " << input << std::endl;
        return false;
    }
    std::vector<Frame> frames;
    if (!reader.extractFrames(frames)) {
        reader.close();
        std::cerr << "No frame in PCAPNG file." << std::endl;
        return false;
    }
    reader.close();

    /* mdflib peut dedupliquer par timestamp; on assure des timestamps strictement croissants */
    std::sort(frames.begin(), frames.end(), [](const Frame& a, const Frame& b) {
        return a.timestampSec < b.timestampSec;
    });

    /* PCAPNG timestamps may be relative (0-based). MDF expects epoch ns. */
    if (!frames.empty() && frames.front().timestampSec < 86400.0) {
        const auto now = std::chrono::system_clock::now();
        const int64_t nowNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        const double epochSec = static_cast<double>(nowNs) / 1e9;
        const double offset = epochSec - frames.front().timestampSec;
        for (auto& f : frames) f.timestampSec += offset;
    }

    for (size_t i = 1; i < frames.size(); ++i) {
        if (frames[i].timestampSec <= frames[i - 1].timestampSec) {
            frames[i].timestampSec = frames[i - 1].timestampSec + 1e-3;  /* 1 ms */
        }
    }

    /* Grouper par type de bus : CAN/CAN_FD, LIN, FlexRay, Ethernet. Un fichier MDF par type. */
    std::map<BusType, std::vector<Frame>> byBus;
    for (auto& f : frames) {
        BusType key = (f.bus == BusType::CAN_FD) ? BusType::CAN : f.bus;
        byBus[key].push_back(std::move(f));
    }

    const bool multipleTypes = byBus.size() > 1;
    size_t totalWritten = 0;

    for (const auto& kv : byBus) {
        const BusType bus = kv.first;
        const std::vector<Frame>& busFrames = kv.second;
        if (busFrames.empty()) continue;

        std::string outPath = outputPathForBus(output, ".mf4", bus, multipleTypes);
        size_t maxPayload = maxPayloadHintForMdfWriter(bus);
        for (const auto& f : busFrames) {
            if (f.data.size() > maxPayload) maxPayload = f.data.size();
        }
        capMaxPayloadToBusLimits(bus, maxPayload);

        MdfFrameWriter writer;
        if (!writer.open(outPath, bus, maxPayload)) {
            std::cerr << "Error: cannot create MDF file: " << outPath << std::endl;
            return false;
        }
        if (!writer.writeFrames(busFrames)) {
            std::cerr << "Error: frame write failed for " << outPath << std::endl;
            writer.close();
            return false;
        }
        writer.close();
        totalWritten += busFrames.size();
        std::cout << "  -> " << outPath << " (" << busFrames.size() << " frame(s) " << busTypeToSuffix(bus) << ")" << std::endl;
    }

    std::cout << "PCAPNG -> MDF conversion completed: " << totalWritten << " frame(s) total." << std::endl;
    return totalWritten > 0;
}

static bool frameEqual(const Frame& a, const Frame& b) {
    if (a.id != b.id || a.dlc != b.dlc || a.data.size() != b.data.size()) return false;
    for (size_t i = 0; i < a.data.size(); ++i) {
        if (a.data[i] != b.data[i]) return false;
    }
    return true;
}

bool ConversionManager::verifyMdfToPcap(const std::string& mdfPath, const std::string& pcapPath, size_t sampleSize) {
    MdfReader mdfReader;
    if (!mdfReader.open(mdfPath)) {
        std::cerr << "Error: cannot open MDF file: " << mdfPath << std::endl;
        return false;
    }
    std::vector<Frame> mdfFrames;
    if (!mdfReader.extractFrames(mdfFrames) || mdfFrames.empty()) {
        mdfReader.close();
        std::cerr << "Error: no bus frames in MDF file." << std::endl;
        return false;
    }
    mdfReader.close();

    PcapReader pcapReader;
    if (!pcapReader.open(pcapPath)) {
        std::cerr << "Error: cannot open PCAP file: " << pcapPath << std::endl;
        return false;
    }
    std::vector<Frame> pcapFrames;
    if (!pcapReader.extractFrames(pcapFrames)) {
        pcapReader.close();
        std::cerr << "Error: no frames in PCAP file." << std::endl;
        return false;
    }
    pcapReader.close();

    auto sortFrames = [](std::vector<Frame>& v) {
        std::sort(v.begin(), v.end(), [](const Frame& a, const Frame& b) {
            if (a.timestampSec != b.timestampSec) return a.timestampSec < b.timestampSec;
            if (a.id != b.id) return a.id < b.id;
            return a.data < b.data;
        });
    };
    sortFrames(mdfFrames);
    sortFrames(pcapFrames);

    const size_t mdfCount = mdfFrames.size();
    const size_t pcapCount = pcapFrames.size();

    std::cout << "\n=== MDF -> PCAP Conformity Check ===" << std::endl;
    std::cout << "MDF frames:  " << mdfCount << std::endl;
    std::cout << "PCAP frames: " << pcapCount << std::endl;

    if (mdfCount != pcapCount) {
        std::cerr << "FAIL: Frame count mismatch (MDF=" << mdfCount << ", PCAP=" << pcapCount << ")" << std::endl;
        return false;
    }

    if (mdfFrames.empty()) {
        std::cout << "OK: Both empty (no frames to compare)" << std::endl;
        return true;
    }

    sampleSize = std::min(sampleSize, mdfCount / 2 + 1);
    std::vector<size_t> indices;
    indices.push_back(0);
    for (size_t i = 1; i < sampleSize; ++i) {
        indices.push_back(i);
        indices.push_back(mdfCount - 1 - i);
    }
    indices.push_back(mdfCount - 1);
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());

    for (size_t idx : indices) {
        if (!frameEqual(mdfFrames[idx], pcapFrames[idx])) {
            std::cerr << "FAIL: Frame " << idx << " mismatch:" << std::endl;
            std::cerr << "  MDF:  ID=" << mdfFrames[idx].id << " DLC=" << (int)mdfFrames[idx].dlc;
            for (uint8_t b : mdfFrames[idx].data) std::cerr << " " << std::hex << (int)b;
            std::cerr << std::dec << std::endl;
            std::cerr << "  PCAP: ID=" << pcapFrames[idx].id << " DLC=" << (int)pcapFrames[idx].dlc;
            for (uint8_t b : pcapFrames[idx].data) std::cerr << " " << std::hex << (int)b;
            std::cerr << std::dec << std::endl;
            return false;
        }
    }

    std::cout << "OK: " << mdfCount << " frames, sample of " << indices.size() << " verified (ID, DLC, Data)" << std::endl;
    return true;
}

bool ConversionManager::verifyPcapToMdf(const std::string& pcapPath, const std::string& mdfPath, size_t sampleSize) {
    PcapReader pcapReader;
    if (!pcapReader.open(pcapPath)) {
        std::cerr << "Error: cannot open PCAP file: " << pcapPath << std::endl;
        return false;
    }
    std::vector<Frame> pcapFrames;
    if (!pcapReader.extractFrames(pcapFrames)) {
        pcapReader.close();
        std::cerr << "Error: no frames in PCAP file." << std::endl;
        return false;
    }
    pcapReader.close();

    MdfReader mdfReader;
    if (!mdfReader.open(mdfPath)) {
        std::cerr << "Error: cannot open MDF file: " << mdfPath << std::endl;
        return false;
    }
    std::vector<Frame> mdfFrames;
    if (!mdfReader.extractFrames(mdfFrames) || mdfFrames.empty()) {
        mdfReader.close();
        std::cerr << "Error: no bus frames in MDF file (MDF may be empty or invalid)." << std::endl;
        return false;
    }
    mdfReader.close();

    auto sortFrames = [](std::vector<Frame>& v) {
        std::sort(v.begin(), v.end(), [](const Frame& a, const Frame& b) {
            if (a.timestampSec != b.timestampSec) return a.timestampSec < b.timestampSec;
            if (a.id != b.id) return a.id < b.id;
            return a.data < b.data;
        });
    };
    sortFrames(pcapFrames);
    sortFrames(mdfFrames);

    const size_t pcapCount = pcapFrames.size();
    const size_t mdfCount = mdfFrames.size();

    std::cout << "\n=== PCAP -> MDF Conformity Check ===" << std::endl;
    std::cout << "PCAP frames: " << pcapCount << std::endl;
    std::cout << "MDF frames:  " << mdfCount << std::endl;

    if (pcapCount != mdfCount) {
        std::cerr << "FAIL: Frame count mismatch (PCAP=" << pcapCount << ", MDF=" << mdfCount << ")" << std::endl;
        return false;
    }

    if (pcapFrames.empty()) {
        std::cout << "OK: Both empty (no frames to compare)" << std::endl;
        return true;
    }

    sampleSize = std::min(sampleSize, mdfCount / 2 + 1);
    std::vector<size_t> indices;
    indices.push_back(0);
    for (size_t i = 1; i < sampleSize; ++i) {
        indices.push_back(i);
        indices.push_back(mdfCount - 1 - i);
    }
    indices.push_back(mdfCount - 1);
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());

    for (size_t idx : indices) {
        if (!frameEqual(pcapFrames[idx], mdfFrames[idx])) {
            std::cerr << "FAIL: Frame " << idx << " mismatch:" << std::endl;
            std::cerr << "  PCAP: ID=" << pcapFrames[idx].id << " DLC=" << (int)pcapFrames[idx].dlc;
            for (uint8_t b : pcapFrames[idx].data) std::cerr << " " << std::hex << (int)b;
            std::cerr << std::dec << std::endl;
            std::cerr << "  MDF:  ID=" << mdfFrames[idx].id << " DLC=" << (int)mdfFrames[idx].dlc;
            for (uint8_t b : mdfFrames[idx].data) std::cerr << " " << std::hex << (int)b;
            std::cerr << std::dec << std::endl;
            return false;
        }
    }

    std::cout << "OK: " << mdfCount << " frames, sample of " << indices.size() << " verified (ID, DLC, Data)" << std::endl;
    return true;
}
