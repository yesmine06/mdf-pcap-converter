#pragma once

#include "../bus/BusTypes.h"
#include "../bus/BusDetector.h"
#include <string>
#include <memory>
#include <fstream>

/**
 * AsciiReader - Lit les fichiers ASCII (MDF/ASCII).
 * Utilise BusDetector pour distinguer trames bus vs signaux.
 * Formats supportes: CAN, LIN (Timestamp, ID, DLC, Data).
 */
class AsciiReader {
public:
    bool open(const std::string& filePath);
    /**
     * Lit la prochaine trame.
     * @return true si trame lue, false si fin de fichier ou ligne signal (ignoree).
     */
    bool readFrame(Frame& frame);
    void close();

private:
    static std::vector<std::string> split(const std::string& s, char delim);
    static std::string trim(const std::string& s);

    std::unique_ptr<std::ifstream> file_;
    BusDetector detector_;
};
