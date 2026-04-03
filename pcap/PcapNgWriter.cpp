#include "PcapNgWriter.h"
#include <array>
#include <cstring>

namespace {

constexpr uint32_t BLOCK_TYPE_SHB = 0x0A0D0D0A;
constexpr uint32_t BLOCK_TYPE_IDB = 0x00000001;
constexpr uint32_t BLOCK_TYPE_EPB = 0x00000006;
constexpr uint32_t BYTE_ORDER_MAGIC = 0x1A2B3C4D;
constexpr uint16_t OPT_ENDOFOPT = 0;
constexpr uint32_t DLT_CAN_SOCKETCAN = 227;
constexpr uint32_t DLT_LIN = 254;
constexpr uint32_t DLT_ETHERNET = 1;
constexpr uint32_t DLT_FLEXRAY = 259;

static uint32_t dltForBus(BusType bus) {
    switch (bus) {
        case BusType::LIN: return DLT_LIN;
        case BusType::FlexRay: return DLT_FLEXRAY;
        case BusType::Ethernet: return DLT_ETHERNET;
        case BusType::CAN:
        case BusType::CAN_FD:
        default: return DLT_CAN_SOCKETCAN;
    }
}

} // namespace

PcapNgWriter::PcapNgWriter() : file_(nullptr), busType_(BusType::CAN) {}

PcapNgWriter::~PcapNgWriter() {
    close();
}

void PcapNgWriter::writeBlockType(uint32_t type) {
    file_->put(type & 0xFF);
    file_->put((type >> 8) & 0xFF);
    file_->put((type >> 16) & 0xFF);
    file_->put((type >> 24) & 0xFF);
}

void PcapNgWriter::writeBlockLength(uint32_t len) {
    file_->put(len & 0xFF);
    file_->put((len >> 8) & 0xFF);
    file_->put((len >> 16) & 0xFF);
    file_->put((len >> 24) & 0xFF);
}

std::vector<uint8_t> PcapNgWriter::buildPacketData(const Frame& frame) {
    std::vector<uint8_t> buf;
    if (frame.bus == BusType::LIN) {
        buf.resize(5 + frame.dlc);
        buf[0] = 1;
        buf[1] = (frame.dlc & 0x0F) | (0 << 4) | (1 << 6);
        buf[2] = static_cast<uint8_t>(frame.id & 0xFF);
        buf[3] = 0;
        buf[4] = 0;
        if (frame.dlc > 0 && !frame.data.empty())
            memcpy(buf.data() + 5, frame.data.data(), frame.dlc);
    } else if (frame.bus == BusType::Ethernet) {
        buf = frame.data;
    } else if (frame.bus == BusType::FlexRay) {
        buf.resize(7 + frame.dlc);
        buf[0] = 0x01 | ((frame.flexRayChannel & 1) << 7);
        buf[1] = 0;
        buf[2] = (frame.id << 1) & 0xFF;
        buf[3] = (frame.id >> 7) & 0x0F;
        buf[4] = (frame.dlc / 2) & 0x7F;
        buf[5] = 0;
        buf[6] = frame.flexRayCycleCount & 0x3F;
        if (frame.dlc > 0 && !frame.data.empty())
            memcpy(buf.data() + 7, frame.data.data(), frame.dlc);
    } else {
        buf.resize(8 + frame.dlc);
        uint32_t idBe = frame.id;
        if (frame.id > 0x7FF) idBe |= 0x80000000u;
        buf[0] = (idBe >> 24) & 0xFF;
        buf[1] = (idBe >> 16) & 0xFF;
        buf[2] = (idBe >> 8) & 0xFF;
        buf[3] = idBe & 0xFF;
        buf[4] = frame.dlc;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = (frame.dlc == 8) ? 9 : 0;
        if (frame.dlc > 0 && !frame.data.empty())
            memcpy(buf.data() + 8, frame.data.data(), frame.dlc);
    }
    return buf;
}

bool PcapNgWriter::open(const std::string& filePath, BusType busType) {
    close();
    file_ = new std::ofstream(filePath, std::ios::binary);
    if (!file_ || !file_->is_open()) {
        delete file_;
        file_ = nullptr;
        return false;
    }
    busType_ = busType;
    if (busType_ == BusType::Unknown) busType_ = BusType::CAN;

    uint32_t dlt = static_cast<uint32_t>(dltForBus(busType_));

    const uint32_t shbLen = 32;
    writeBlockType(BLOCK_TYPE_SHB);
    writeBlockLength(shbLen);
    file_->put(0x4D); file_->put(0x3C); file_->put(0x2B); file_->put(0x1A);
    file_->put(1); file_->put(0);
    file_->put(0); file_->put(0);
    file_->put(0xFF); file_->put(0xFF); file_->put(0xFF); file_->put(0xFF);
    file_->put(0xFF); file_->put(0xFF); file_->put(0xFF); file_->put(0xFF);
    file_->put(OPT_ENDOFOPT & 0xFF); file_->put((OPT_ENDOFOPT >> 8) & 0xFF);
    file_->put(0); file_->put(0);
    writeBlockLength(shbLen);

    const uint32_t idbLen = 24;
    writeBlockType(BLOCK_TYPE_IDB);
    writeBlockLength(idbLen);
    file_->put(dlt & 0xFF);
    file_->put((dlt >> 8) & 0xFF);
    file_->put(0); file_->put(0);
    file_->put(0xFF); file_->put(0xFF);
    file_->put(0xFF); file_->put(0xFF);
    file_->put(OPT_ENDOFOPT & 0xFF); file_->put((OPT_ENDOFOPT >> 8) & 0xFF);
    file_->put(0); file_->put(0);
    writeBlockLength(idbLen);

    return true;
}

void PcapNgWriter::writeFrame(const Frame& frame) {
    if (!file_ || !file_->is_open()) return;

    /* PCAPNG EPB : timestamp en nanosecondes. Calcul direct pour eviter perte de precision. */
    const uint64_t ts_ns = static_cast<uint64_t>(frame.timestampSec * 1000000000.0 + 0.5);
    uint32_t ts_high = static_cast<uint32_t>(ts_ns >> 32);
    uint32_t ts_low = static_cast<uint32_t>(ts_ns & 0xFFFFFFFF);

    auto packetData = buildPacketData(frame);
    size_t padLen = (4 - (packetData.size() & 3)) & 3;
    uint32_t epbBodyLen = 20 + static_cast<uint32_t>(packetData.size()) + static_cast<uint32_t>(padLen);
    uint32_t epbTotalLen = 12 + epbBodyLen;

    writeBlockType(BLOCK_TYPE_EPB);
    writeBlockLength(epbTotalLen);
    file_->put(0); file_->put(0); file_->put(0); file_->put(0);
    file_->put(ts_high & 0xFF);
    file_->put((ts_high >> 8) & 0xFF);
    file_->put((ts_high >> 16) & 0xFF);
    file_->put((ts_high >> 24) & 0xFF);
    file_->put(ts_low & 0xFF);
    file_->put((ts_low >> 8) & 0xFF);
    file_->put((ts_low >> 16) & 0xFF);
    file_->put((ts_low >> 24) & 0xFF);
    uint32_t capLen = static_cast<uint32_t>(packetData.size());
    file_->put(capLen & 0xFF);
    file_->put((capLen >> 8) & 0xFF);
    file_->put((capLen >> 16) & 0xFF);
    file_->put((capLen >> 24) & 0xFF);
    file_->put(capLen & 0xFF);
    file_->put((capLen >> 8) & 0xFF);
    file_->put((capLen >> 16) & 0xFF);
    file_->put((capLen >> 24) & 0xFF);
    file_->write(reinterpret_cast<const char*>(packetData.data()), packetData.size());
    for (size_t i = 0; i < padLen; ++i) file_->put(0);
    writeBlockLength(epbTotalLen);
}

void PcapNgWriter::close() {
    if (file_) {
        if (file_->is_open()) {
            file_->flush();
            file_->close();
        }
        delete file_;
        file_ = nullptr;
    }
}
