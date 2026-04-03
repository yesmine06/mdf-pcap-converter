#include "PcapNgReader.h"
#include "../bus/BusTypes.h"
#include <algorithm>
#include <cstring>

namespace {

constexpr uint32_t BLOCK_TYPE_SHB = 0x0A0D0D0A;
constexpr uint32_t BLOCK_TYPE_IDB = 0x00000001;
constexpr uint32_t BLOCK_TYPE_EPB = 0x00000006;
constexpr uint32_t DLT_CAN_SOCKETCAN = 227;
constexpr uint32_t DLT_LIN = 254;
constexpr uint32_t DLT_ETHERNET = 1;
constexpr uint32_t DLT_FLEXRAY = 259;

#pragma pack(push, 1)
struct SocketCanHeader {
    uint32_t can_id;
    uint8_t payload_len;
    uint8_t fd_flags;
    uint8_t reserved1;
    uint8_t len8_dlc;
};
#pragma pack(pop)

static uint32_t read32(std::istream& in) {
    uint8_t b[4];
    in.read(reinterpret_cast<char*>(b), 4);
    if (in.gcount() != 4) return 0;
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}

} // namespace

PcapNgReader::PcapNgReader() : file_(nullptr), nextInterfaceId_(0), queueIdx_(0) {}

PcapNgReader::~PcapNgReader() {
    close();
}

bool PcapNgReader::open(const std::string& filePath) {
    close();
    file_ = new std::ifstream(filePath, std::ios::binary);
    if (!file_ || !file_->is_open()) {
        delete file_;
        file_ = nullptr;
        return false;
    }
    interfaceToDlt_.clear();
    nextInterfaceId_ = 0;
    frameQueue_.clear();
    queueIdx_ = 0;
    return true;
}

bool PcapNgReader::readNextBlock() {
    if (!file_ || !file_->is_open()) return false;

    while (true) {
        uint32_t blockType = read32(*file_);
        uint32_t blockLen = read32(*file_);
        if (blockLen < 12 || !file_->good()) return false;

        const size_t bodyLen = blockLen - 12;
        std::vector<uint8_t> body(bodyLen);
        file_->read(reinterpret_cast<char*>(body.data()), bodyLen);
        if (file_->gcount() != static_cast<std::streamsize>(bodyLen)) return false;

        uint32_t blockLen2 = read32(*file_);
        if (blockLen2 != blockLen) return false;

        switch (blockType) {
            case BLOCK_TYPE_SHB:
                interfaceToDlt_.clear();
                nextInterfaceId_ = 0;
                break;
            case BLOCK_TYPE_IDB:
                if (bodyLen >= 4) {
                    uint32_t dlt = body[0] | (body[1] << 8) | (body[2] << 16) | (body[3] << 24);
                    interfaceToDlt_[nextInterfaceId_++] = dlt;
                }
                break;
            case BLOCK_TYPE_EPB: {
                uint32_t interfaceId = (bodyLen >= 4) ? (body[0] | (body[1] << 8) | (body[2] << 16) | (body[3] << 24)) : 0;
                uint32_t dlt = 0;
                auto it = interfaceToDlt_.find(interfaceId);
                if (it != interfaceToDlt_.end()) dlt = it->second;
                return parseEpb(body.data(), bodyLen, dlt);
            }
            default:
                break;
        }
    }
}

bool PcapNgReader::parseEpb(const uint8_t* data, size_t len, uint32_t dlt) {
    if (len < 20) return true;

    uint64_t tsHigh = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
    uint64_t tsLow = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
    uint64_t tsNs = (tsHigh << 32) | tsLow;
    double tsSec = static_cast<double>(tsNs) / 1e9;

    uint32_t capLen = data[12] | (data[13] << 8) | (data[14] << 16) | (data[15] << 24);
    uint32_t origLen = data[16] | (data[17] << 8) | (data[18] << 16) | (data[19] << 24);
    (void)origLen;

    if (capLen > len - 20) capLen = static_cast<uint32_t>(len - 20);
    const uint8_t* payload = data + 20;

    Frame frame;
    if (dlt == DLT_CAN_SOCKETCAN && capLen >= 8) {
        /* SocketCAN : CAN ID en big-endian (comme PcapWriter/PcapNgWriter) */
        uint32_t rawCanId = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
        uint32_t canId = rawCanId & 0x1FFFFFFF;
        uint8_t dlc = payload[4];
        if (dlc > 64) dlc = 64;  /* CAN FD jusqu'à 64 octets */

        frame.bus = (rawCanId & 0x80000000) ? BusType::CAN_FD : BusType::CAN;
        frame.timestampSec = tsSec;
        frame.id = canId;
        frame.dlc = dlc;
        frame.data.clear();
        if (dlc > 0 && capLen >= 8 + dlc) {
            frame.data.assign(payload + 8, payload + 8 + dlc);
        }
        frameQueue_.push_back(frame);
    } else if (dlt == DLT_LIN && capLen >= 5) {
        uint8_t payloadLen = payload[1] & 0x0F;
        if (payloadLen > 8) payloadLen = 8;
        frame.bus = BusType::LIN;
        frame.timestampSec = tsSec;
        frame.id = payload[2] & 0xFF;
        frame.dlc = payloadLen;
        frame.data.clear();
        if (payloadLen > 0 && capLen >= 5 + payloadLen) {
            frame.data.assign(payload + 5, payload + 5 + payloadLen);
        }
        frameQueue_.push_back(frame);
    } else if (dlt == DLT_ETHERNET && capLen >= 14) {
        frame.bus = BusType::Ethernet;
        frame.timestampSec = tsSec;
        frame.id = (payload[12] << 8) | payload[13];
        frame.dlc = static_cast<uint8_t>(capLen > 255 ? 255 : capLen);
        frame.data.assign(payload, payload + capLen);
        frameQueue_.push_back(frame);
    } else if (dlt == DLT_FLEXRAY && capLen >= 8) {
        uint8_t typeIndex = payload[0] & 0x7F;
        if (typeIndex == 0x01) {
            uint16_t frameId = ((payload[2] >> 1) & 0x7F) | (static_cast<uint16_t>(payload[3] & 0x0F) << 7);
            size_t plen = (capLen >= 7) ? (capLen - 7) : 0;
            if (plen > 254) plen = 254;
            frame.bus = BusType::FlexRay;
            frame.timestampSec = tsSec;
            frame.id = frameId & 0x7FF;
            frame.dlc = static_cast<uint8_t>(plen);
            frame.flexRayChannel = (payload[0] >> 7) & 1;
            frame.flexRayCycleCount = (capLen >= 7) ? (payload[6] & 0x3F) : 0;
            frame.flexRaySegment = (frame.id >= 1 && frame.id <= 31)
                ? FlexRaySegment::Static : FlexRaySegment::Dynamic;
            frame.data.clear();
            if (plen > 0 && capLen >= 7) {
                frame.data.assign(payload + 7, payload + 7 + plen);
            }
            frameQueue_.push_back(frame);
        }
    }
    return true;
}

bool PcapNgReader::readFrame(Frame& frame) {
    while (queueIdx_ >= frameQueue_.size()) {
        frameQueue_.clear();
        queueIdx_ = 0;
        if (!readNextBlock()) return false;
    }
    frame = frameQueue_[queueIdx_++];
    return true;
}

bool PcapNgReader::extractFrames(std::vector<Frame>& out) {
    out.clear();
    if (!file_ || !file_->is_open()) return false;

    frameQueue_.clear();
    queueIdx_ = 0;

    while (readNextBlock()) {
        for (const auto& f : frameQueue_) out.push_back(f);
        frameQueue_.clear();
    }
    return !out.empty();
}

void PcapNgReader::close() {
    if (file_) {
        if (file_->is_open()) file_->close();
        delete file_;
        file_ = nullptr;
    }
    interfaceToDlt_.clear();
    nextInterfaceId_ = 0;
    frameQueue_.clear();
    queueIdx_ = 0;
}
