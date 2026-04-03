#pragma once

#include "../bus/BusTypes.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

/**
 * MdfReader - Lecture MDF4/MF4 via mdflib
 * - convertToAscii() : sortie fichiers .asc (optionnel)
 * - extractFrames() : extrait trames CAN directement (interne, pas de fichier)
 */
class MdfReader {
public:
    MdfReader() = default;
    ~MdfReader();

    bool open(const std::string& filePath);
    bool convertToAscii(const std::string& outputBasePath);
    bool convertToAscii(const std::string& outputBasePath, std::vector<std::string>& outPaths);
    bool convertBusGroupsToAscii(const std::string& outputBasePath, std::vector<std::string>& outPaths);
    bool extractFrames(std::vector<Frame>& out);
    void listChannelGroupNames(std::vector<std::string>& out);
    void listChannelGroupInfo(std::vector<std::pair<std::string, std::string>>& out);
    bool getFirstBusGroupObserverNames(std::string& groupName, std::vector<std::string>& observerNames);
    /** Retourne le temps de debut de mesure (ns depuis 1970) ou 0 si indisponible. */
    uint64_t getMeasurementStartTimeNs() const;
    void close();

private:
    std::string filePath_;
    void* mdfReader_ = nullptr;  // mdf::MdfReader* (opaque)
};
