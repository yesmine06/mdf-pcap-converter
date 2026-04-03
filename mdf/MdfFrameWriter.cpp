#include "MdfFrameWriter.h"
#include <mdf/mdffactory.h>
#include <mdf/mdfwriter.h>
#include <mdf/canmessage.h>
#include <mdf/iheader.h>
#include <mdf/ifilehistory.h>
#include <mdf/idatagroup.h>
#include <mdf/ichannelgroup.h>
#include <mdf/isourceinformation.h>
#include <iostream>
#include <algorithm>

namespace {

// mdflib CreateBusLogConfiguration ne supporte que CAN. On utilise la structure CAN
// comme conteneur pour tous les types (LIN, FlexRay, Ethernet ont id/dlc/data).
constexpr uint32_t MAX_PAYLOAD_CAN = 64;
constexpr uint32_t MAX_PAYLOAD_ETH = 1518;

} // namespace

struct MdfFrameWriterImpl {
    mdf::MdfWriter* writer = nullptr;
    size_t maxPayload = 64;
    BusType busType = BusType::CAN;
};

static const char* cgNameForBus(BusType bus) {
    switch (bus) {
        case BusType::LIN:       return "LIN_DataFrame";
        case BusType::FlexRay:   return "FlexRay_DataFrame";
        case BusType::Ethernet:  return "Ethernet_DataFrame";
        case BusType::CAN:
        case BusType::CAN_FD:
        default:                 return "CAN_DataFrame";
    }
}

MdfFrameWriter::MdfFrameWriter() : writer_(nullptr) {}

MdfFrameWriter::~MdfFrameWriter() {
    close();
}

bool MdfFrameWriter::open(const std::string& filePath, BusType busType, size_t maxPayload) {
    close();
    filePath_ = filePath;

    auto* w = mdf::MdfFactory::CreateMdfWriterEx(mdf::MdfWriterType::MdfBusLogger);
    if (!w) return false;

    if (!w->Init(filePath)) {
        delete w;
        return false;
    }

    /* Metadonnees requises pour compatibilite MDF4 / asammdf */
    auto* header = w->Header();
    if (header) {
        auto* history = header->CreateFileHistory();
        if (history) {
            history->Description("PCAP to MDF conversion");
            history->ToolName("mdf2ascii");
            history->ToolVendor("converter");
            history->ToolVersion("1.0");
        }
    }

    mdf::MdfBusType mdfBus = mdf::MdfBusType::CAN;
    switch (busType) {
        case BusType::LIN:       mdfBus = mdf::MdfBusType::LIN; break;
        case BusType::FlexRay:   mdfBus = mdf::MdfBusType::FlexRay; break;
        case BusType::Ethernet:  mdfBus = mdf::MdfBusType::Ethernet; break;
        case BusType::CAN:
        case BusType::CAN_FD:
        default:                 mdfBus = mdf::MdfBusType::CAN; break;
    }
    w->BusType(mdfBus);
    /* VlsdStorage requis par asammdf pour la vue bus trace */
    w->StorageType(mdf::MdfStorageType::VlsdStorage);
    uint32_t len = static_cast<uint32_t>(std::min(std::max(maxPayload, size_t(8)), size_t(MAX_PAYLOAD_ETH)));
    w->MaxLength(len);
    w->PreTrigTime(0.0);
    w->CompressData(false);

    if (!w->CreateBusLogConfiguration()) {
        delete w;
        return false;
    }

    /* SourceInformation (SI) avec Bus requis par asammdf pour afficher les trames */
    mdf::BusType siBus = mdf::BusType::Can;
    switch (busType) {
        case BusType::LIN:       siBus = mdf::BusType::Lin; break;
        case BusType::FlexRay:   siBus = mdf::BusType::FlexRay; break;
        case BusType::Ethernet:  siBus = mdf::BusType::Ethernet; break;
        default:                 siBus = mdf::BusType::Can; break;
    }
    auto* lastDg = w->Header() ? w->Header()->LastDataGroup() : nullptr;
    if (lastDg) {
        for (auto* cg : lastDg->ChannelGroups()) {
            if (!cg) continue;
            /* Ignorer le CG VLSD (nom vide) - pas de SI necessaire */
            const std::string cgName = cg->Name();
            if (cgName.empty()) continue;
            auto* si = cg->SourceInformation();
            if (!si) si = cg->CreateSourceInformation();
            if (si) {
                si->Type(mdf::SourceType::Bus);
                si->Bus(siBus);
                si->Name(cgName);
                si->Path(cgName);
                si->Description("Bus logging");
            }
        }
    }

    auto* impl = new MdfFrameWriterImpl();
    impl->maxPayload = static_cast<size_t>(std::min(std::max(maxPayload, size_t(8)), size_t(MAX_PAYLOAD_ETH)));
    impl->writer = w;
    impl->busType = busType;
    writer_ = impl;
    return true;
}

bool MdfFrameWriter::writeFrames(const std::vector<Frame>& frames) {
    if (!writer_ || frames.empty()) return false;

    auto* impl = static_cast<MdfFrameWriterImpl*>(writer_);
    mdf::MdfWriter* w = impl->writer;

    auto* header = w->Header();
    if (!header) return false;

    auto* lastDg = header->LastDataGroup();
    if (!lastDg) return false;

    /* CG selon type de bus : CAN_DataFrame, LIN_DataFrame, FlexRay_DataFrame, Ethernet_DataFrame */
    const char* cgName = cgNameForBus(impl->busType);
    auto* dataFrameCg = lastDg->GetChannelGroup(cgName);
    if (!dataFrameCg) {
        const auto cgList = lastDg->ChannelGroups();
        for (auto* cg : cgList) {
            if (cg && (cg->Flags() & mdf::CgFlag::VlsdChannel) == 0) {
                const std::string n = cg->Name();
                if (n == cgName || n.find("DataFrame") != std::string::npos) {
                    dataFrameCg = cg;
                    break;
                }
                if (!dataFrameCg) dataFrameCg = cg;  /* fallback: premier non-VLSD */
            }
        }
    }
    if (!dataFrameCg) {
        std::cerr << "[MdfFrameWriter] ChannelGroup not found: " << cgName << std::endl;
        return false;
    }

    /* Timestamps en nanosecondes (epoch UTC). Calcul direct pour precision. */
    auto toNs = [](double sec) -> uint64_t {
        return static_cast<uint64_t>(sec * 1000000000.0 + 0.5);
    };
    uint64_t startNs = toNs(frames.front().timestampSec);
    uint64_t stopNs = toNs(frames.back().timestampSec);
    if (stopNs <= startNs) stopNs = startNs + 1;

    if (!w->InitMeasurement()) return false;

    w->StartMeasurement(startNs);

    const size_t maxLen = impl->maxPayload;
    for (const auto& f : frames) {
        mdf::CanMessage msg;
        msg.MessageId(f.id);
        msg.ExtendedId(f.id > 0x7FF);
        msg.BusChannel(1);  /* canal >= 1 requis par asammdf */
        msg.Rtr(false);

        std::vector<uint8_t> data = f.data;
        if (data.size() > maxLen) data.resize(maxLen);
        msg.DataBytes(data);

        uint64_t tsNs = toNs(f.timestampSec);
        w->SaveCanMessage(*dataFrameCg, tsNs, msg);
    }

    w->StopMeasurement(stopNs);
    if (!w->FinalizeMeasurement()) return false;

    return true;
}

void MdfFrameWriter::close() {
    if (writer_) {
        auto* impl = static_cast<MdfFrameWriterImpl*>(writer_);
        delete impl->writer;
        delete impl;
        writer_ = nullptr;
    }
    filePath_.clear();
}
