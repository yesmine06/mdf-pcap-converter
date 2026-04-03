#include "BusDetector.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace {

bool matchesCol(const std::string& col, const char* pattern) {
    if (col.empty()) return false;
    std::string c = col, p = pattern;
    std::transform(c.begin(), c.end(), c.begin(), ::tolower);
    std::transform(p.begin(), p.end(), p.begin(), ::tolower);
    return c.find(p) != std::string::npos || p.find(c) != std::string::npos;
}

bool parseId(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    std::string t = s;
    if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        t = t.substr(2);
        char* end = nullptr;
        unsigned long val = std::strtoul(t.c_str(), &end, 16);
        if (end && *end) return false;
        out = static_cast<uint32_t>(val);
        return true;
    }
    char* end = nullptr;
    unsigned long val = std::strtoul(t.c_str(), &end, 10);
    if (end && *end) return false;
    out = static_cast<uint32_t>(val);
    return true;
}

bool parseDataBytes(const std::string& s, std::vector<uint8_t>& out) {
    out.clear();
    std::string t = s;
    t.erase(std::remove_if(t.begin(), t.end(), ::isspace), t.end());
    if (t.empty()) return true;
    if (t.size() % 2 != 0) return false;
    for (size_t i = 0; i < t.size(); i += 2) {
        char* end = nullptr;
        unsigned long v = std::strtoul(t.substr(i, 2).c_str(), &end, 16);
        if (end && *end) return false;
        if (v > 0xFF) return false;
        out.push_back(static_cast<uint8_t>(v));
    }
    return true;
}

} // namespace

bool BusDetector::isConvertibleToPcap(BusType bus) {
    return bus == BusType::CAN || bus == BusType::CAN_FD || bus == BusType::LIN ||
           bus == BusType::FlexRay || bus == BusType::Ethernet;
}

bool BusDetector::feedHeader(const std::vector<std::string>& headers) {
    colTime_ = -1; colId_ = -1; colDlc_ = -1; colData_ = -1;
    busType_ = BusType::Unknown;
    for (size_t i = 0; i < headers.size(); ++i) {
        const std::string& h = headers[i];
        if (matchesCol(h, "time") || matchesCol(h, "timestamp")) colTime_ = static_cast<int>(i);
        else if ((h == "ID" || h.find(".ID") != std::string::npos || (matchesCol(h, "id") && h.find("IDE") == std::string::npos)))
            colId_ = static_cast<int>(i);
        else if (h == "DLC" || matchesCol(h, "dlc") || h.find("DataLength") != std::string::npos)
            colDlc_ = static_cast<int>(i);
        else if (h == "Data" || matchesCol(h, "databytes") || (matchesCol(h, "data") && h.find("Length") == std::string::npos))
            colData_ = static_cast<int>(i);
    }
    if (colTime_ < 0) colTime_ = 0;
    if (colId_ < 0 || colData_ < 0) {
        formatDetected_ = true;
        return false;
    }
    for (const auto& h : headers) {
        std::string l = h;
        std::transform(l.begin(), l.end(), l.begin(), ::tolower);
        if (l.find("lin") != std::string::npos && l.find("id") != std::string::npos) {
            busType_ = BusType::LIN;
            formatDetected_ = true;
            return true;
        }
        if (l.find("flexray") != std::string::npos || l.find("flex_ray") != std::string::npos) {
            busType_ = BusType::FlexRay;
            formatDetected_ = true;
            return true;
        }
        if (l.find("ethernet") != std::string::npos || l.find("someip") != std::string::npos || l.find("mac") != std::string::npos) {
            busType_ = BusType::Ethernet;
            formatDetected_ = true;
            return true;
        }
    }
    busType_ = BusType::CAN;
    formatDetected_ = true;
    return true;
}

bool BusDetector::isBusFrame(const std::vector<std::string>& parts, BusType& busType, Frame& frame) {
    if (parts.size() < 2) return false;

    if (!formatDetected_) {
        bool looksLikeHeader = (parts[0] == "Timestamp" || parts[0] == "time" ||
            (parts[0].size() > 0 && !std::isdigit(static_cast<unsigned char>(parts[0][0])) &&
             parts[0][0] != '.' && parts[0][0] != '-'));
        if (looksLikeHeader) {
            feedHeader(parts);
            return false;
        }
        formatDetected_ = true;
        busType_ = (parts.size() >= 4) ? BusType::CAN : BusType::Unknown;
        colTime_ = 0; colId_ = 1; colDlc_ = 2; colData_ = 3;
    }

    if (busType_ == BusType::Unknown) return false;
    if (static_cast<size_t>(colTime_) >= parts.size() || static_cast<size_t>(colId_) >= parts.size() ||
        static_cast<size_t>(colData_) >= parts.size()) return false;
    if (colDlc_ >= 0 && static_cast<size_t>(colDlc_) >= parts.size()) return false;

    char* tsEnd = nullptr;
    const double ts = std::strtod(parts[colTime_].c_str(), &tsEnd);
    if (tsEnd == parts[colTime_].c_str()) return false;  /* parse failed */
    uint32_t id = 0;
    if (!parseId(parts[colId_], id)) return false;
    std::vector<uint8_t> data;
    if (!parseDataBytes(parts[colData_], data)) return false;
    if (data.size() > 1518) return false;

    int dlc = 0;
    if (colDlc_ >= 0) {
        char* dlcEnd = nullptr;
        long dlcVal = std::strtol(parts[colDlc_].c_str(), &dlcEnd, 10);
        if (dlcEnd == parts[colDlc_].c_str() || dlcVal < 0 || dlcVal > 255) return false;
        dlc = static_cast<int>(dlcVal);
    } else {
        dlc = static_cast<int>(data.size());
    }
    if (dlc > 0 && static_cast<size_t>(dlc) < data.size()) data.resize(dlc);

    busType = busType_;
    if (busType == BusType::LIN && id > 63) busType = BusType::CAN;
    if (busType == BusType::CAN && id > 0x1FFFFFFF) busType = BusType::CAN_FD;

    frame.bus = busType;
    frame.timestampSec = ts;
    frame.id = id;
    frame.dlc = static_cast<uint8_t>(data.size());
    frame.data = std::move(data);
    return true;
}
