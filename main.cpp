#include "ConversionManager.h"
#include <iostream>
#include <string>
#include <algorithm>
#include <cstdlib>
#include <filesystem>

/** Repertoire de sortie par defaut. Priorite: CONVERTER_OUTPUT_DIR, puis chemin par defaut. */
static std::string getOutputDir() {
    const char* env = std::getenv("CONVERTER_OUTPUT_DIR");
    if (env && env[0]) return std::string(env);
    return "D:\\yesmine\\3eme\\PFE\\fichiers\\fichiers-convertis";
}

/** Extrait le nom de base du fichier (sans extension) depuis un chemin. */
static std::string getBaseFilename(const std::string& path) {
    size_t sep = path.find_last_of("/\\");
    std::string name = (sep != std::string::npos) ? path.substr(sep + 1) : path;
    size_t dot = name.find_last_of('.');
    return (dot != std::string::npos && dot > 0) ? name.substr(0, dot) : name;
}

/** Insere -output avant l'extension (ex: sortie.pcap -> sortie-output.pcap). */
static std::string addOutputSuffix(const std::string& path) {
    const size_t dot = path.find_last_of('.');
    const size_t sep = path.find_last_of("/\\");
    if (dot != std::string::npos && (sep == std::string::npos || dot > sep)) {
        return path.substr(0, dot) + "-output" + path.substr(dot);
    }
    return path + "-output";
}

/** Construit le chemin de sortie par defaut : OUTPUT_DIR + nom_base + -output + extension. */
static std::string defaultOutputPath(const std::string& inputPath, const std::string& ext) {
    std::string base = getBaseFilename(inputPath);
    std::filesystem::path dir(getOutputDir());
    std::filesystem::create_directories(dir);
    return (dir / (base + "-output" + ext)).string();
}

void printUsage(const char* programName) {
    std::cout << "MDF/ASCII/PCAP/PCAPNG Converter\n\n";
    std::cout << "Default output: " << getOutputDir() << " (set CONVERTER_OUTPUT_DIR to override)\n\n";
    std::cout << "MDF -> PCAP/PCAPNG (direct):\n";
    std::cout << "  " << programName << " --mdf2pcap <file.mf4> [output.pcap]\n";
    std::cout << "  " << programName << " --mdf2pcapng <file.mf4> [output.pcapng]\n\n";
    std::cout << "PCAP/PCAPNG -> MDF:\n";
    std::cout << "  " << programName << " --pcap2mdf <file.pcap> [output.mf4]\n";
    std::cout << "  " << programName << " --pcapng2mdf <file.pcapng> [output.mf4]\n\n";
    std::cout << "MDF -> ASCII (optional):\n";
    std::cout << "  " << programName << " <file.mf4|mdf> [output]\n\n";
    std::cout << "ASCII -> PCAP/PCAPNG:\n";
    std::cout << "  " << programName << " --ascii2pcap <file.asc> [output.pcap]\n";
    std::cout << "  " << programName << " --ascii2pcapng <file.asc> [output.pcapng]\n\n";
    std::cout << "Supported ASCII CAN formats:\n";
    std::cout << "  - Standard: Timestamp\\tID\\tDLC\\tData\n";
    std::cout << "  - With header: auto-detect (time, ID, DLC, Data/DataBytes)\n";
    std::cout << "  - ID in decimal or hex (0x123). Measurement files: not convertible to PCAP.\n\n";
    std::cout << "Verify MDF -> PCAP conformity:\n";
    std::cout << "  " << programName << " --verify-mdf2pcap <file.mf4> <file.pcap>\n\n";
    std::cout << "Verify PCAP -> MDF conformity:\n";
    std::cout << "  " << programName << " --verify-pcap2mdf <file.pcap> <file.mf4>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string arg1 = argv[1];
    bool mdf2pcap = (arg1 == "--mdf2pcap" || arg1 == "-m");
    bool mdf2pcapng = (arg1 == "--mdf2pcapng");
    bool pcap2mdf = (arg1 == "--pcap2mdf" || arg1 == "-p");
    bool pcapng2mdf = (arg1 == "--pcapng2mdf");
    bool ascii2pcap = (arg1 == "--ascii2pcap" || arg1 == "-a");
    bool ascii2pcapng = (arg1 == "--ascii2pcapng" || arg1 == "-n");
    bool verifyMdf2pcap = (arg1 == "--verify-mdf2pcap" || arg1 == "-v");
    bool verifyPcap2mdf = (arg1 == "--verify-pcap2mdf");

    if (verifyMdf2pcap) {
        if (argc < 4) {
            std::cerr << "Error: specify MDF and PCAP files.\n";
            std::cerr << "Usage: " << argv[0] << " --verify-mdf2pcap <file.mf4> <file.pcap>\n";
            return 1;
        }
        ConversionManager manager;
        return manager.verifyMdfToPcap(argv[2], argv[3]) ? 0 : 1;
    }

    if (verifyPcap2mdf) {
        if (argc < 4) {
            std::cerr << "Error: specify PCAP and MDF files.\n";
            std::cerr << "Usage: " << argv[0] << " --verify-pcap2mdf <file.pcap> <file.mf4>\n";
            return 1;
        }
        ConversionManager manager;
        return manager.verifyPcapToMdf(argv[2], argv[3]) ? 0 : 1;
    }

    if (pcap2mdf || pcapng2mdf) {
        if (argc < 3) {
            std::cerr << "Error: specify the PCAP/PCAPNG file.\n";
            printUsage(argv[0]);
            return 1;
        }
        std::string inputPath = argv[2];
        std::string outputPath;
        if (argc >= 4) {
            outputPath = addOutputSuffix(argv[3]);
        } else {
            outputPath = defaultOutputPath(inputPath, ".mf4");
        }
        ConversionManager manager;
        return (pcapng2mdf ? manager.pcapngToMdf(inputPath, outputPath)
                           : manager.pcapToMdf(inputPath, outputPath)) ? 0 : 1;
    }

    if (mdf2pcap || mdf2pcapng) {
        if (argc < 3) {
            std::cerr << "Error: specify the MDF file.\n";
            printUsage(argv[0]);
            return 1;
        }
        std::string inputPath = argv[2];
        std::string outputPath;
        if (argc >= 4) {
            outputPath = addOutputSuffix(argv[3]);
        } else {
            outputPath = defaultOutputPath(inputPath, mdf2pcapng ? ".pcapng" : ".pcap");
        }
        ConversionManager manager;
        return (mdf2pcapng ? manager.mdfToPcapng(inputPath, outputPath)
                           : manager.mdfToPcap(inputPath, outputPath)) ? 0 : 1;
    }

    if (ascii2pcap || ascii2pcapng) {
        if (argc < 3) {
            std::cerr << "Error: specify the ASCII file.\n";
            printUsage(argv[0]);
            return 1;
        }
        std::string inputPath = argv[2];
        std::string outputPath;
        if (argc >= 4) {
            outputPath = addOutputSuffix(argv[3]);
        } else {
            outputPath = defaultOutputPath(inputPath, ascii2pcapng ? ".pcapng" : ".pcap");
        }
        ConversionManager manager;
        return (ascii2pcapng ? manager.asciiToPcapng(inputPath, outputPath)
                            : manager.asciiToPcap(inputPath, outputPath)) ? 0 : 1;
    }

    std::string inputPath = argv[1];
    std::string outputPath;
    if (argc >= 3) {
        outputPath = addOutputSuffix(argv[2]);
    } else {
        outputPath = defaultOutputPath(inputPath, ".asc");
    }

    ConversionManager manager;
    return manager.mdfToAscii(inputPath, outputPath) ? 0 : 1;
}
