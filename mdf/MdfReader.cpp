#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <functional>

#include <mdf/mdfreader.h>
#include <mdf/mdfhelper.h>
#include <mdf/iheader.h>
#include <mdf/ichannelgroup.h>
#include <mdf/ichannelobserver.h>
#include <mdf/isourceinformation.h>

#include "MdfReaderWrapper.h"
#include "../bus/BusTypes.h"

static bool isCanChannelGroup(const std::string& name) {
    return name == "CAN_DataFrame" || name == "CAN_RemoteFrame" ||
           name == "CAN_ErrorFrame" || name == "CAN_OverloadFrame";
}

static bool isBusFrameChannelGroup(const std::string& name) {
    if (isCanChannelGroup(name)) return true;
    if (name.find("LIN_") == 0 || name == "LIN_DataFrame") return true;
    if (name.find("FlexRay") != std::string::npos) return true;
    if (name.find("Ethernet") != std::string::npos) return true;
    if (name.find("CAN") != std::string::npos && (name.find("_Rx") != std::string::npos || name.find("_Tx") != std::string::npos)) return true;
    if (name.find("LIN") != std::string::npos && name.find("Frame") != std::string::npos) return true;
    return false;
}

/**
 * Exclude diagnostic / non-frame groups. Must NOT skip CAN_ErrorFrame: name contains "Error"
 * and was previously dropped entirely, so bus errors never reached PCAP/ASC (convertBusGroupsToAscii).
 */
static bool skipChannelGroupForBusExport(const std::string& cgName) {
    if (cgName == "CAN_ErrorFrame" || cgName == "CAN_OverloadFrame")
        return false;
    if (cgName.find("RTR") != std::string::npos) return true;
    if (cgName.find("ChecksumError") != std::string::npos ||
        cgName.find("ReceiveError") != std::string::npos ||
        cgName.find("SynchronizationError") != std::string::npos ||
        cgName.find("TransmissionError") != std::string::npos)
        return true;
    if (cgName.find("Error") != std::string::npos) return true;
    return false;
}

static BusType getBusTypeFromChannelGroup(const std::string& name) {
    if (name.find("LIN") != std::string::npos) return BusType::LIN;
    if (name.find("FlexRay") != std::string::npos) return BusType::FlexRay;
    if (name.find("Ethernet") != std::string::npos) return BusType::Ethernet;
    return BusType::CAN;
}

/** Max payload bytes per bus when reading MDF VLSD/DataBytes into Frame (PCAP export). */
static size_t maxPayloadForBus(BusType bus) {
    switch (bus) {
        case BusType::Ethernet:
            return 1518;
        case BusType::FlexRay:
            return 254;
        case BusType::CAN_FD:
        case BusType::CAN:
            return 64; /* CAN FD max; classic uses ≤8 */
        case BusType::LIN:
        default:
            return 8;
    }
}

static const mdf::IChannelObserver* findObserver(
    const mdf::ChannelObserverList& observers,
    const std::function<bool(const std::string&)>& pred) {
    for (const auto& o : observers) {
        if (!o) continue;
        if (pred(o->Name())) return o.get();
    }
    return nullptr;
}

static bool parseHexStringToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    std::string s;
    for (char c : hex) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            s += c;
    }
    if (s.size() % 2 != 0) return false;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexVal(s[i]), lo = hexVal(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return true;
}

static void writeCanAscii(
    std::ofstream& out,
    const mdf::ChannelObserverList& observers,
    uint64_t nofSamples,
    const std::string& cgName = {}) {
    const bool isCanErrorGroup = (cgName == "CAN_ErrorFrame");
    const mdf::IChannelObserver* master = nullptr;
    for (const auto& o : observers) {
        if (o && o->IsMaster()) { master = o.get(); break; }
    }
    if (!master) {
        master = findObserver(observers, [](const std::string& n) {
            return n == "Timestamp" || n == "time" || n.find("Timestamp") != std::string::npos;
        });
    }
    if (!master && !observers.empty()) master = observers[0].get();

    const auto* idObs = findObserver(observers, [](const std::string& n) {
        if (n.find(".IDE") != std::string::npos || (n.size() >= 3 && n.substr(0, 3) == "IDE")) return false;
        return (n.find(".ID") != std::string::npos || n.find(".id") != std::string::npos || n == "ID" ||
                n.find("LIN_ID") != std::string::npos || n.find("MessageId") != std::string::npos ||
                n.find("FrameID") != std::string::npos) && n.find("IDE") == std::string::npos;
    });
    const auto* dlcObs = findObserver(observers, [](const std::string& n) {
        return n.find(".DLC") != std::string::npos || n.find("DataLength") != std::string::npos ||
               n == "DLC" || n.find("Length") != std::string::npos;
    });
    const auto* dataObs = findObserver(observers, [](const std::string& n) {
        return n.find("DataBytes") != std::string::npos || n == "Data" ||
               n.find("Payload") != std::string::npos;
    });
    if (!master || !idObs || !dataObs) return;

    out << "Timestamp\tID\tDLC\tData\n";
    for (uint64_t s = 0; s < nofSamples; ++s) {
        std::string tsStr;
        if (!master->GetEngValue(s, tsStr)) continue;
        uint64_t idVal = 0;
        if (!idObs->GetChannelValue(s, idVal)) {
            std::string idStr;
            if (!idObs->GetEngValue(s, idStr)) continue;
            idVal = std::strtoull(idStr.c_str(), nullptr, 0);
        }
        idVal &= 0x1FFFFFFF;  /* CAN 29-bit, LIN/FlexRay dans plage */
        /* Correction: si ID mal lu (ex. 0x7000000 au lieu de 0x7) - valeur dans octet haut */
        if (idVal > 0x7FF && (idVal & 0x00FFFFFFU) == 0)
            idVal = idVal >> 24;
        int dlcVal = 0;
        if (dlcObs) {
            uint64_t dlcU = 0;
            if (dlcObs->GetChannelValue(s, dlcU)) dlcVal = static_cast<int>(dlcU);
        }
        std::vector<uint8_t> dataVec;
        if (!dataObs->GetChannelValue(s, dataVec)) {
            std::string dataStr;
            if (!dataObs->GetEngValue(s, dataStr) || !parseHexStringToBytes(dataStr, dataVec)) {
                if (!isCanErrorGroup) continue;
                dataVec.clear();
            }
        }
        /* Sans canal DLC : prendre la longueur réelle des données (Ethernet / FlexRay / etc.). */
        if (dlcVal <= 0 || dlcVal > static_cast<int>(dataVec.size())) dlcVal = static_cast<int>(dataVec.size());
        if (static_cast<size_t>(dlcVal) < dataVec.size()) dataVec.resize(static_cast<size_t>(dlcVal));

        std::ostringstream line;
        line << tsStr << "\t0x" << std::hex << idVal << "\t" << std::dec << dlcVal << "\t";
        for (size_t i = 0; i < dataVec.size(); ++i) {
            if (i > 0) line << " ";
            line << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(dataVec[i]);
        }
        out << line.str() << "\n";
    }
}

static void extractBusFrames(
    const mdf::ChannelObserverList& observers,
    uint64_t nofSamples,
    BusType bus,
    std::vector<Frame>& out,
    const std::string& cgName = {}) {
    const bool isCanErrorGroup = (cgName == "CAN_ErrorFrame");
    const mdf::IChannelObserver* master = nullptr;
    for (const auto& o : observers) {
        if (o && o->IsMaster()) { master = o.get(); break; }
    }
    if (!master) {
        master = findObserver(observers, [](const std::string& n) {
            return n == "Timestamp" || n == "time" || n.find("Timestamp") != std::string::npos;
        });
    }
    if (!master && !observers.empty()) {
        master = observers[0].get();
    }
    const auto* idObs = findObserver(observers, [](const std::string& n) {
        if (n.find(".IDE") != std::string::npos || n.find("IDE") == 0) return false;
        return (n.find(".ID") != std::string::npos || n == "ID" || n.find("LIN_ID") != std::string::npos ||
                n.find("MessageId") != std::string::npos || n.find("FrameID") != std::string::npos) &&
               n.find("IDE") == std::string::npos;
    });
    const auto* dlcObs = findObserver(observers, [](const std::string& n) {
        return n.find(".DLC") != std::string::npos || n.find("DataLength") != std::string::npos ||
               n == "DLC" || n.find("Length") != std::string::npos;
    });
    const auto* dataObs = findObserver(observers, [](const std::string& n) {
        return n.find("DataBytes") != std::string::npos || n == "Data" ||
               n.find("Payload") != std::string::npos;
    });
    if (!master || !idObs || !dataObs) return;

    const size_t maxPayload = maxPayloadForBus(bus);

    for (uint64_t s = 0; s < nofSamples; ++s) {
        double tsVal = 0.0;
        if (!master->GetEngValue(s, tsVal)) {
            std::string tsStr;
            if (!master->GetEngValue(s, tsStr)) continue;
            tsVal = std::atof(tsStr.c_str());
        }
        uint64_t idVal = 0;
        if (!idObs->GetChannelValue(s, idVal)) {
            std::string idStr;
            if (!idObs->GetEngValue(s, idStr)) continue;
            idVal = std::strtoull(idStr.c_str(), nullptr, 0);
        }
        idVal &= 0x1FFFFFFF;  /* CAN 29-bit, LIN/FlexRay dans plage */
        if (idVal > 0x7FF && (idVal & 0x00FFFFFFU) == 0)
            idVal = idVal >> 24;
        int dlcVal = dlcObs ? 0 : static_cast<int>(maxPayload);
        if (dlcObs) {
            uint64_t dlcU = 0;
            if (dlcObs->GetChannelValue(s, dlcU)) dlcVal = static_cast<int>(dlcU);
        }
        std::vector<uint8_t> dataVec;
        if (!dataObs->GetChannelValue(s, dataVec)) {
            std::string dataStr;
            if (!dataObs->GetEngValue(s, dataStr) || !parseHexStringToBytes(dataStr, dataVec)) {
                if (!isCanErrorGroup) continue;
                dataVec.clear();
            }
        }
        if (dataVec.size() > maxPayload) dataVec.resize(maxPayload);
        if (dlcVal <= 0 || static_cast<size_t>(dlcVal) > maxPayload)
            dlcVal = static_cast<int>(dataVec.size());
        /* Tronquer au DLC reel : MDF padde a 8 octets, PCAP n'ecrit que les octets utiles */
        if (static_cast<size_t>(dlcVal) < dataVec.size())
            dataVec.resize(static_cast<size_t>(dlcVal));

        Frame f;
        f.bus = bus;
        f.timestampSec = tsVal;
        f.id = static_cast<uint32_t>(idVal);
        f.dlc = static_cast<uint8_t>(dlcVal);
        f.data = std::move(dataVec);
        /* Reste BusType::CAN pour le CG CAN_DataFrame (évite 2 PCAP si FD mélangé). DLC peut aller à 64 (FD). */
        out.push_back(std::move(f));
    }
}

// PIMPL: masquer mdflib dans le .cpp (eviter conflit de noms)
using MdfLibReader = mdf::MdfReader;
struct MdfReaderImpl {
    std::unique_ptr<MdfLibReader> reader;
};

MdfReader::~MdfReader() {
    close();
}

bool MdfReader::open(const std::string& filePath) {
    close();
    filePath_ = filePath;

    std::ifstream probe(filePath, std::ios::binary);
    if (!probe.good()) {
        std::cerr << "[MdfReader] File not found or inaccessible: " << filePath << std::endl;
        return false;
    }
    probe.close();

    if (!mdf::IsMdfFile(filePath)) {
        std::cerr << "[MdfReader] Not an MDF file (invalid or corrupted format): " << filePath << std::endl;
        return false;
    }

    mdfReader_ = new MdfReaderImpl();
    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    impl->reader = std::make_unique<MdfLibReader>(filePath);

    if (!impl->reader->IsOk()) {
        std::cerr << "[MdfReader] Invalid MDF file: " << filePath << std::endl;
        close();
        return false;
    }

    if (!impl->reader->ReadEverythingButData()) {
        std::cerr << "[MdfReader] Error reading structure: " << filePath << std::endl;
        close();
        return false;
    }

    return true;
}

static std::string stripFilename(const std::string& text) {
    std::ostringstream out;
    for (char c : text) {
        if (c == '_' || c == '-' || (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            out << c;
        }
    }
    return out.str();
}

bool MdfReader::convertToAscii(const std::string& outputBasePath) {
    std::vector<std::string> dummy;
    return convertToAscii(outputBasePath, dummy);
}

bool MdfReader::convertToAscii(const std::string& outputBasePath, std::vector<std::string>& outPaths) {
    outPaths.clear();
    if (!mdfReader_) return false;

    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    const auto* header = impl->reader->GetHeader();
    if (!header) return false;

    const auto dgList = header->DataGroups();
    if (dgList.empty()) {
        std::cerr << "[MdfReader] No data group." << std::endl;
        return false;
    }

    size_t fileCount = 0;
    const std::string baseName = outputBasePath;
    /* Trouver le dernier point apres le dernier separateur de chemin (evite C:\a.b\file) */
    const size_t lastSep = baseName.find_last_of("/\\");
    const size_t lastDot = baseName.find_last_of('.');
    const bool hasExt = (lastDot != std::string::npos) && (lastSep == std::string::npos || lastDot > lastSep);
    const std::string stem = hasExt ? baseName.substr(0, lastDot) : baseName;
    std::string outDir = stem.find_first_of("/\\") != std::string::npos
        ? stem.substr(0, stem.find_last_of("/\\") + 1) : "";

    for (size_t dgIdx = 0; dgIdx < dgList.size(); ++dgIdx) {
        auto* dg = dgList[dgIdx];
        if (!dg) continue;

        const auto cgList = dg->ChannelGroups();
        std::vector<const mdf::IChannelGroup*> validCg;
        for (auto* cg : cgList) {
            if (!cg) continue;
            if ((cg->Flags() & mdf::CgFlag::VlsdChannel) != 0) continue;
            if (cg->NofSamples() == 0) continue;
            validCg.push_back(cg);
        }

        for (size_t cgIdx = 0; cgIdx < validCg.size(); ++cgIdx) {
            const auto* cg = validCg[cgIdx];
            mdf::ChannelObserverList observers;
            mdf::CreateChannelObserverForChannelGroup(*dg, *cg, observers);

            if (observers.empty()) continue;

            if (!impl->reader->ReadData(*dg)) {
                std::cerr << "[MdfReader] Error reading data DG" << dgIdx << std::endl;
                continue;
            }

            std::string ascPath = stem;
            if (dgList.size() > 1) ascPath += "_DG" + std::to_string(dgIdx);
            if (validCg.size() > 1) {
                const std::string cgName = cg->Name();
                ascPath += cgName.empty()
                    ? "_CG" + std::to_string(cgIdx)
                    : "_" + stripFilename(cgName);
            }
            ascPath += ".asc";

            std::ofstream out(ascPath);
            if (!out.is_open()) {
                std::cerr << "[MdfReader] Cannot create: " << ascPath << std::endl;
                continue;
            }

            const uint64_t nofSamples = observers[0]->NofSamples();
            const std::string cgName = cg->Name();

            if (isBusFrameChannelGroup(cgName)) {
                writeCanAscii(out, observers, nofSamples, cgName);
            } else {
                std::vector<const mdf::IChannelObserver*> masterFirst;
                for (const auto& o : observers) {
                    if (o && o->IsMaster()) masterFirst.push_back(o.get());
                }
                for (const auto& o : observers) {
                    if (o && !o->IsMaster()) masterFirst.push_back(o.get());
                }

                const char sep = '\t';
                for (size_t i = 0; i < masterFirst.size(); ++i) {
                    if (i > 0) out << sep;
                    out << masterFirst[i]->Name();
                }
                out << "\n";

                for (uint64_t s = 0; s < nofSamples; ++s) {
                    for (size_t i = 0; i < masterFirst.size(); ++i) {
                        if (i > 0) out << sep;
                        std::string val;
                        if (masterFirst[i]->GetEngValue(s, val)) {
                            out << val;
                        }
                    }
                    out << "\n";
                }
            }

            out.close();
            std::cout << "  -> " << ascPath << " (" << nofSamples << " lines)" << std::endl;
            ++fileCount;
            if (isBusFrameChannelGroup(cg->Name())) outPaths.push_back(ascPath);

            dg->ClearData();
        }
    }

    return fileCount > 0;
}

bool MdfReader::convertBusGroupsToAscii(const std::string& outputBasePath, std::vector<std::string>& outPaths) {
    outPaths.clear();
    if (!mdfReader_) return false;

    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    const auto* header = impl->reader->GetHeader();
    if (!header) return false;

    const auto dgList = header->DataGroups();
    const size_t dotPos = outputBasePath.find_last_of(".\\/");
    const std::string stem = (dotPos != std::string::npos && outputBasePath[dotPos] == '.')
        ? outputBasePath.substr(0, dotPos) : outputBasePath;

    for (size_t dgIdx = 0; dgIdx < dgList.size(); ++dgIdx) {
        auto* dg = dgList[dgIdx];
        if (!dg) continue;

        const auto cgList = dg->ChannelGroups();
        for (size_t cgIdx = 0; cgIdx < cgList.size(); ++cgIdx) {
            auto* cg = cgList[cgIdx];
            if (!cg || (cg->Flags() & mdf::CgFlag::VlsdChannel) != 0 || cg->NofSamples() == 0) continue;
            const std::string cgName = cg->Name();
            if (!isBusFrameChannelGroup(cgName)) continue;
            if (skipChannelGroupForBusExport(cgName)) continue;

            if (!impl->reader->ReadData(*dg)) continue;

            mdf::ChannelObserverList observers;
            mdf::CreateChannelObserverForChannelGroup(*dg, *cg, observers);
            if (observers.empty()) { dg->ClearData(); continue; }

            std::string ascPath = stem;
            if (dgList.size() > 1) ascPath += "_DG" + std::to_string(dgIdx);
            ascPath += "_" + stripFilename(cgName) + ".asc";

            std::ofstream out(ascPath);
            if (!out.is_open()) continue;

            writeCanAscii(out, observers, observers[0]->NofSamples(), cgName);
            out.close();
            outPaths.push_back(ascPath);
            dg->ClearData();
        }
    }
    return !outPaths.empty();
}

bool MdfReader::extractFrames(std::vector<Frame>& out) {
    if (!mdfReader_) return false;
    out.clear();

    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    const auto* header = impl->reader->GetHeader();
    if (!header) return false;

    const auto dgList = header->DataGroups();
    for (size_t dgIdx = 0; dgIdx < dgList.size(); ++dgIdx) {
        auto* dg = dgList[dgIdx];
        if (!dg) continue;

        const auto cgList = dg->ChannelGroups();
        /* Observers must be created BEFORE ReadData - they receive samples during the read */
        std::vector<std::pair<mdf::IChannelGroup*, mdf::ChannelObserverList>> cgObservers;
        for (auto* cg : cgList) {
            if (!cg || (cg->Flags() & mdf::CgFlag::VlsdChannel) != 0 || cg->NofSamples() == 0)
                continue;
            const std::string cgName = cg->Name();
            if (skipChannelGroupForBusExport(cgName)) continue;

            mdf::ChannelObserverList observers;
            mdf::CreateChannelObserverForChannelGroup(*dg, *cg, observers);
            if (observers.empty()) continue;

            cgObservers.emplace_back(cg, std::move(observers));
        }
        if (cgObservers.empty()) continue;

        if (!impl->reader->ReadData(*dg)) continue;

        for (auto& pair : cgObservers) {
            const BusType bus = isBusFrameChannelGroup(pair.first->Name())
                ? getBusTypeFromChannelGroup(pair.first->Name())
                : BusType::CAN;
            extractBusFrames(pair.second, pair.second[0]->NofSamples(), bus, out, pair.first->Name());
        }
        dg->ClearData();
    }
    return !out.empty();
}

void MdfReader::listChannelGroupNames(std::vector<std::string>& out) {
    out.clear();
    std::vector<std::pair<std::string, std::string>> info;
    listChannelGroupInfo(info);
    for (const auto& p : info) out.push_back(p.first);
}

uint64_t MdfReader::getMeasurementStartTimeNs() const {
    if (!mdfReader_) return 0;
    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    const auto* header = impl->reader->GetHeader();
    return header ? header->StartTime() : 0;
}

static const char* mdfBusTypeToStr(mdf::BusType bt) {
    switch (bt) {
        case mdf::BusType::Can: return "CAN";
        case mdf::BusType::Lin: return "LIN";
        case mdf::BusType::FlexRay: return "FlexRay";
        case mdf::BusType::Ethernet: return "Ethernet";
        case mdf::BusType::Most: return "MOST";
        case mdf::BusType::Kline: return "KLINE";
        case mdf::BusType::Usb: return "USB";
        default: return nullptr;
    }
}

bool MdfReader::getFirstBusGroupObserverNames(std::string& groupName, std::vector<std::string>& observerNames) {
    observerNames.clear();
    groupName.clear();
    if (!mdfReader_) return false;

    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    const auto* header = impl->reader->GetHeader();
    if (!header) return false;

    for (auto* dg : header->DataGroups()) {
        if (!dg || !impl->reader->ReadData(*dg)) continue;
        for (auto* cg : dg->ChannelGroups()) {
            if (!cg || (cg->Flags() & mdf::CgFlag::VlsdChannel) != 0 || cg->NofSamples() == 0) continue;
            const std::string& name = cg->Name();
            if (name.find("RTR") != std::string::npos || name.find("Error") != std::string::npos) continue;
            if (name.find("CAN") == std::string::npos && name.find("LIN") == std::string::npos) continue;

            mdf::ChannelObserverList observers;
            mdf::CreateChannelObserverForChannelGroup(*dg, *cg, observers);
            groupName = name;
            for (const auto& o : observers) {
                if (o) observerNames.push_back(o->Name());
            }
            dg->ClearData();
            return !observerNames.empty();
        }
        dg->ClearData();
    }
    return false;
}

void MdfReader::listChannelGroupInfo(std::vector<std::pair<std::string, std::string>>& out) {
    out.clear();
    if (!mdfReader_) return;

    auto* impl = static_cast<MdfReaderImpl*>(mdfReader_);
    const auto* header = impl->reader->GetHeader();
    if (!header) return;

    for (auto* dg : header->DataGroups()) {
        if (!dg) continue;
        for (auto* cg : dg->ChannelGroups()) {
            if (!cg || (cg->Flags() & mdf::CgFlag::VlsdChannel) != 0) continue;
            std::string name = cg->Name();
            if (name.empty()) continue;
            std::string info;
            if (const auto* si = cg->SourceInformation()) {
                if (const char* s = mdfBusTypeToStr(si->Bus())) info = s;
            }
            info += " | samples=" + std::to_string(cg->NofSamples());
            out.emplace_back(std::move(name), std::move(info));
        }
    }
}

void MdfReader::close() {
    if (mdfReader_) {
        delete static_cast<MdfReaderImpl*>(mdfReader_);
        mdfReader_ = nullptr;
    }
    filePath_.clear();
}
