#include "PcapWriter.h"
#include <array>
#include <vector>
#include <cstring>

namespace {

constexpr uint32_t PCAP_MAGIC_USEC = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_NSEC = 0xa1b23c4d;
constexpr uint16_t PCAP_VERSION_MAJOR = 2;
constexpr uint16_t PCAP_VERSION_MINOR = 4;
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

// LIN: 5-byte header per LINKTYPE_LIN
// [0]=msg_format_rev(1), [1]=payload_len|msg_type|cks_type, [2]=PID, [3]=checksum, [4]=errors

static void write32(uint32_t val, std::ostream& out) {
    std::array<uint8_t, 4> b;
    b[0] =  val        & 0xFF;
    b[1] = (val >> 8)  & 0xFF;
    b[2] = (val >> 16) & 0xFF;
    b[3] = (val >> 24) & 0xFF;
    out.write(reinterpret_cast<char*>(b.data()), 4);
}

static void write32be(uint32_t val, std::ostream& out) {
    std::array<uint8_t, 4> b;
    b[0] = (val >> 24) & 0xFF;
    b[1] = (val >> 16) & 0xFF;
    b[2] = (val >> 8)  & 0xFF;
    b[3] =  val        & 0xFF;
    out.write(reinterpret_cast<char*>(b.data()), 4);
}

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

PcapWriter::PcapWriter() : file_(nullptr), busType_(BusType::CAN) {}

PcapWriter::~PcapWriter() {
    close();
}

bool PcapWriter::open(const std::string& filePath, BusType busType, bool useNanoseconds) {
    close();
    file_ = new std::ofstream(filePath, std::ios::binary);
    if (!file_ || !file_->is_open()) {
        delete file_;
        file_ = nullptr;
        return false;
    }
    busType_ = busType;
    useNanoseconds_ = useNanoseconds;
    if (busType_ == BusType::Unknown) busType_ = BusType::CAN;

    PcapGlobalHeader hdr{};
    hdr.magic = useNanoseconds_ ? PCAP_MAGIC_NSEC : PCAP_MAGIC_USEC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = dltForBus(busType_);
    file_->write(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    return true;
}

void PcapWriter::writeFrame(const Frame& frame) {
    if (!file_ || !file_->is_open()) return;

    /* Calcul precis : eviter perte de precision via double->int->frac */
    uint32_t ts_sec;
    uint32_t ts_frac;
    if (useNanoseconds_) {
        const uint64_t ts_ns = static_cast<uint64_t>(frame.timestampSec * 1000000000.0 + 0.5);
        ts_sec = static_cast<uint32_t>(ts_ns / 1000000000ULL);
        ts_frac = static_cast<uint32_t>(ts_ns % 1000000000ULL);
    } else {
        ts_sec = static_cast<uint32_t>(frame.timestampSec);
        double frac = frame.timestampSec - ts_sec;
        ts_frac = static_cast<uint32_t>(frac * 1000000.0 + 0.5);
    }

    size_t packetLen = 0;
    std::vector<uint8_t> packetBuf;

    if (frame.bus == BusType::LIN) {
        packetBuf.resize(5 + frame.dlc);
        packetBuf[0] = 1;
        packetBuf[1] = (frame.dlc & 0x0F) | (0 << 4) | (1 << 6);
        packetBuf[2] = static_cast<uint8_t>(frame.id & 0xFF);
        packetBuf[3] = 0;
        packetBuf[4] = 0;
        if (frame.dlc > 0 && !frame.data.empty())
            memcpy(packetBuf.data() + 5, frame.data.data(), frame.dlc);
        packetLen = packetBuf.size();
    } else if (frame.bus == BusType::Ethernet) {
        packetBuf = frame.data;
        packetLen = packetBuf.size();
    } else if (frame.bus == BusType::FlexRay) {
        packetBuf.resize(7 + frame.dlc);
        packetBuf[0] = 0x01 | ((frame.flexRayChannel & 1) << 7);
        packetBuf[1] = 0;
        packetBuf[2] = (frame.id << 1) & 0xFF;
        packetBuf[3] = (frame.id >> 7) & 0x0F;
        packetBuf[4] = (frame.dlc / 2) & 0x7F;
        packetBuf[5] = 0;
        packetBuf[6] = frame.flexRayCycleCount & 0x3F;
        if (frame.dlc > 0 && !frame.data.empty())
            memcpy(packetBuf.data() + 7, frame.data.data(), frame.dlc);
        packetLen = packetBuf.size();
    } else {
        SocketCanHeader canHdr{};
        canHdr.can_id = frame.id;
        if (frame.id > 0x7FF) canHdr.can_id |= 0x80000000u;
        canHdr.payload_len = frame.dlc;
        canHdr.fd_flags = 0;
        canHdr.reserved1 = 0;
        canHdr.len8_dlc = (frame.dlc == 8) ? 9 : 0;
        packetLen = 8 + frame.dlc;
        packetBuf.resize(packetLen);
        uint32_t idVal = (frame.id > 0x7FF) ? (frame.id | 0x80000000u) : frame.id;
        /* SocketCAN: CAN ID et flags en BIG-ENDIAN (tcpdump.org/LINKTYPE_CAN_SOCKETCAN) */
        packetBuf[0] = (idVal >> 24) & 0xFF;
        packetBuf[1] = (idVal >> 16) & 0xFF;
        packetBuf[2] = (idVal >> 8) & 0xFF;
        packetBuf[3] = idVal & 0xFF;
        packetBuf[4] = frame.dlc;
        packetBuf[5] = 0;
        packetBuf[6] = 0;
        packetBuf[7] = (frame.dlc == 8) ? 9 : 0;
        if (frame.dlc > 0 && !frame.data.empty())
            memcpy(packetBuf.data() + 8, frame.data.data(), frame.dlc);
    }

    PcapPacketHeader pktHdr{};
    pktHdr.ts_sec = ts_sec;
    pktHdr.ts_usec = ts_frac;  /* usec ou nsec selon format */
    pktHdr.incl_len = static_cast<uint32_t>(packetLen);
    pktHdr.orig_len = static_cast<uint32_t>(packetLen);

    write32(pktHdr.ts_sec, *file_);
    write32(pktHdr.ts_usec, *file_);
    write32(pktHdr.incl_len, *file_);
    write32(pktHdr.orig_len, *file_);
    file_->write(reinterpret_cast<const char*>(packetBuf.data()), packetLen);
}

void PcapWriter::close() {
    if (file_) {
        if (file_->is_open()) {
            file_->flush();
            file_->close();
        }
        delete file_;
        file_ = nullptr;
    }
}
