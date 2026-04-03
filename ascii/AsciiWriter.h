#pragma once

#include <string>
#include "../model/Frame.h"
#include <fstream>

class AsciiWriter {
public:
    AsciiWriter();
    ~AsciiWriter();

    bool create(const std::string& filePath);
    void writeFrame(const Frame& frame);
    void close();

    bool isOpen() const { return outputFile_.is_open(); }

private:
    std::ofstream outputFile_;
};
