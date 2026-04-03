#include "AsciiReader.h"
#include <sstream>
#include <algorithm>
#include <cctype>

std::string AsciiReader::trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> AsciiReader::split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream iss(s);
    std::string part;
    while (std::getline(iss, part, delim)) {
        parts.push_back(trim(part));
    }
    return parts;
}

bool AsciiReader::open(const std::string& filePath) {
    close();
    file_ = std::make_unique<std::ifstream>(filePath);
    return file_ && file_->is_open();
}

bool AsciiReader::readFrame(Frame& frame) {
    if (!file_ || !file_->is_open()) return false;

    std::string line;
    while (std::getline(*file_, line)) {
        line = trim(line);
        if (line.empty()) continue;

        std::vector<std::string> parts = split(line, '\t');
        if (parts.size() < 2) parts = split(line, ',');
        if (parts.size() < 2) continue;

        BusType busType;
        if (detector_.isBusFrame(parts, busType, frame)) {
            if (BusDetector::isConvertibleToPcap(busType))
                return true;
        }
    }
    return false;
}

void AsciiReader::close() {
    file_.reset();
}
