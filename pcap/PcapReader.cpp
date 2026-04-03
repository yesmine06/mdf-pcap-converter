#include "PcapReader.h"
#include "../bus/BusTypes.h"
#include <algorithm>
#include <cstring>

namespace {

constexpr uint32_t PCAP_MAGIC_LE = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_LE_NSEC = 0xa1b23c4d;
constexpr uint32_t PCAP_MAGIC_BE = 0xd4c3b2a1;
constexpr uint32_t PCAP_MAGIC_BE_NSEC = 0x4d3cb2a1;
constexpr uint32_t DLT_CAN_SOCKETCAN = 227;
constexpr uint32_t DLT_LIN = 254;
constexpr uint32_t DLT_ETHERNET = 1;
constexpr uint32_t DLT_FLEXRAY = 259;

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

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

static uint32_t swap32(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v & 0xFF0000) >> 8) | ((v & 0xFF000000) >> 24);
}

} // namespace

PcapReader::PcapReader() : file_(nullptr), dlt_(0), bigEndian_(false) {}

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open(const std::string& filePath) {
    close();
    file_ = new std::ifstream(filePath, std::ios::binary);
    if (!file_ || !file_->is_open()) {
        delete file_;
        file_ = nullptr;
        return false;
    }

    uint32_t magic = read32(*file_);
    if (magic == 0) { close(); return false; }

    bigEndian_ = (magic == PCAP_MAGIC_BE || magic == PCAP_MAGIC_BE_NSEC);
    usecResolution_ = (magic == PCAP_MAGIC_LE || magic == PCAP_MAGIC_BE);
    if (magic != PCAP_MAGIC_LE && magic != PCAP_MAGIC_LE_NSEC &&
        magic != PCAP_MAGIC_BE && magic != PCAP_MAGIC_BE_NSEC) {
        close();
        return false;
    }

    auto readHdr32 = [this](uint32_t& out) {
        out = read32(*file_);
        if (bigEndian_) out = swap32(out);
    };
    uint32_t tmp;
    readHdr32(tmp);
    readHdr32(tmp);
    readHdr32(tmp);
    readHdr32(tmp);
    readHdr32(tmp);
    dlt_ = tmp & 0xFFFF;
    return true;
}

bool PcapReader::readFrame(Frame& frame) {
    if (!file_ || !file_->is_open()) return false;

    uint32_t tsSec = read32(*file_);
    uint32_t tsUsec = read32(*file_);
    uint32_t inclLen = read32(*file_);
    uint32_t origLen = read32(*file_);
    if (bigEndian_) {
        tsSec = swap32(tsSec);
        tsUsec = swap32(tsUsec);
        inclLen = swap32(inclLen);
        origLen = swap32(origLen);
    }
    (void)origLen;

    if (inclLen > 65535) return false;

    std::vector<uint8_t> packet(inclLen);
    file_->read(reinterpret_cast<char*>(packet.data()), inclLen);
    if (file_->gcount() != static_cast<std::streamsize>(inclLen)) return false;

    double frac = usecResolution_
        ? (static_cast<double>(tsUsec) / 1000000.0)
        : (static_cast<double>(tsUsec) / 1000000000.0);
    double tsSecD = static_cast<double>(tsSec) + frac;

    if (dlt_ == DLT_CAN_SOCKETCAN && inclLen >= 8) {
        const auto* canHdr = reinterpret_cast<const SocketCanHeader*>(packet.data());
        /* CAN ID dans le payload SocketCAN est toujours big-endian (tcpdump.org) */
        uint32_t rawCanId = swap32(canHdr->can_id);
        uint32_t canId = rawCanId & 0x1FFFFFFF;
        uint8_t dlc = canHdr->payload_len;
        if (dlc > 64) dlc = 64;

        frame.bus = (rawCanId & 0x80000000) ? BusType::CAN_FD : BusType::CAN;
        frame.timestampSec = tsSecD;
        frame.id = canId;
        frame.dlc = dlc;
        frame.data.clear();
        if (dlc > 0 && inclLen >= 8u + dlc) {
            frame.data.assign(packet.data() + 8, packet.data() + 8 + dlc);
        }
        return true;
    }

    if (dlt_ == DLT_LIN && inclLen >= 5) {
        uint8_t payloadLen = packet[1] & 0x0F;
        if (payloadLen > 8) payloadLen = 8;
        frame.bus = BusType::LIN;
        frame.timestampSec = tsSecD;
        frame.id = packet[2] & 0xFF;
        frame.dlc = payloadLen;
        frame.data.clear();
        if (payloadLen > 0 && inclLen >= 5u + payloadLen) {
            frame.data.assign(packet.data() + 5, packet.data() + 5 + payloadLen);
        }
        return true;
    }

    if (dlt_ == DLT_ETHERNET && inclLen >= 14) {
        frame.bus = BusType::Ethernet;
        frame.timestampSec = tsSecD;
        frame.id = (packet[12] << 8) | packet[13];
        frame.dlc = static_cast<uint8_t>(inclLen > 255 ? 255 : inclLen);
        frame.data.assign(packet.data(), packet.data() + inclLen);
        return true;
    }

    if (dlt_ == DLT_FLEXRAY && inclLen >= 2) {
        uint8_t typeIndex = packet[0] & 0x7F;
        if (typeIndex == 0x02) {
            /* FlexRay Symbol Packet : ignorer et passer au paquet suivant */
            return readFrame(frame);
        }
        if (typeIndex == 0x01 && inclLen >= 7) {
            uint16_t frameId = ((packet[2] >> 1) & 0x7F) | (static_cast<uint16_t>(packet[3] & 0x0F) << 7);
            size_t payloadLen = (inclLen >= 7) ? (inclLen - 7) : 0;
            if (payloadLen > 254) payloadLen = 254;
            frame.bus = BusType::FlexRay;
            frame.timestampSec = tsSecD;
            frame.id = frameId & 0x7FF;
            frame.dlc = static_cast<uint8_t>(payloadLen);
            frame.flexRayChannel = (packet[0] >> 7) & 1;
            frame.flexRayCycleCount = (inclLen >= 7) ? (packet[6] & 0x3F) : 0;
            frame.flexRaySegment = (frame.id >= 1 && frame.id <= 31)
                ? FlexRaySegment::Static : FlexRaySegment::Dynamic;
            frame.data.clear();
            if (payloadLen > 0 && inclLen >= 7) {
                frame.data.assign(packet.data() + 7, packet.data() + 7 + payloadLen);
            }
            return true;
        }
    }

    return false;
}

bool PcapReader::extractFrames(std::vector<Frame>& out) {
    out.clear();
    if (!file_ || !file_->is_open()) return false;

    Frame frame;
    while (readFrame(frame)) {
        out.push_back(frame);
    }
    return !out.empty();
}

void PcapReader::close() {
    if (file_) {
        if (file_->is_open()) file_->close();
        delete file_;
        file_ = nullptr;
    }
    dlt_ = 0;
    bigEndian_ = false;
    usecResolution_ = true;
}
