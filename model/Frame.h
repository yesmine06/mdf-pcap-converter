#pragma once

#include <vector>
#include <cstdint>

struct Frame {
    uint64_t timestamp;
    uint32_t id;
    uint8_t dlc;
    std::vector<uint8_t> data;
};
