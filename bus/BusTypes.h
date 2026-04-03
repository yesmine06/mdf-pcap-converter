#pragma once

#include <cstdint>
#include <vector>

/**
 * Types de bus supportes par le convertisseur.
 * Trames = ID/Adresse + longueur + donnees -> convertibles en PCAP.
 * Signaux = valeurs continues timestampees -> non convertibles.
 */
enum class BusType {
    CAN,
    CAN_FD,
    LIN,
    FlexRay,
    Ethernet,
    Unknown
};

/** Segment FlexRay : Static ou Dynamic (derive du slot ID si config inconnue). */
enum class FlexRaySegment { Unknown = 0, Static = 1, Dynamic = 2 };

/**
 * Trame interne multi-bus.
 * Utilisee par BusDetector et Conversion Engine.
 * Pour FlexRay : id = slot ID, flexRayCycleCount/Channel/Segment completes.
 */
struct Frame {
    BusType bus = BusType::Unknown;
    double timestampSec = 0.0;
    uint32_t id = 0;
    uint8_t dlc = 0;
    std::vector<uint8_t> data;
    /* FlexRay : cycle (0-63), channel (0=A, 1=B), segment (derive du slot) */
    uint8_t flexRayCycleCount = 0;
    uint8_t flexRayChannel = 0;
    FlexRaySegment flexRaySegment = FlexRaySegment::Unknown;
};
