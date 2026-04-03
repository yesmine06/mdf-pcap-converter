/**
 * Tests de non-regression par flux de conversion.
 * Verifie la preservation du nombre de trames sur chaque flux.
 */
#include "../ConversionManager.h"
#include "../mdf/MdfReaderWrapper.h"
#include "../ascii/AsciiReader.h"
#include "../pcap/PcapReader.h"
#include "../pcap/PcapNgReader.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static int g_failed = 0;
static int g_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "  FAIL: " << (msg) << std::endl; \
        ++g_failed; \
    } else { \
        ++g_passed; \
    } \
} while(0)

static size_t countFramesInPcap(const std::string& path) {
    PcapReader r;
    if (!r.open(path)) return 0;
    std::vector<Frame> frames;
    r.extractFrames(frames);
    r.close();
    return frames.size();
}

static size_t countFramesInPcapng(const std::string& path) {
    PcapNgReader r;
    if (!r.open(path)) return 0;
    std::vector<Frame> frames;
    r.extractFrames(frames);
    r.close();
    return frames.size();
}

static size_t countFramesInMdf(const std::string& path) {
    MdfReader r;
    if (!r.open(path)) return 0;
    std::vector<Frame> frames;
    r.extractFrames(frames);
    r.close();
    return frames.size();
}

/** Compte les trames via MDF->ASCII (utilise pour les MDF generes par MdfFrameWriter). */
static size_t countFramesViaAscii(const std::string& mdfPath) {
    MdfReader r;
    if (!r.open(mdfPath)) return 0;
    std::string basePath = mdfPath;
    const size_t lastDot = basePath.find_last_of('.');
    if (lastDot != std::string::npos) basePath = basePath.substr(0, lastDot);
    basePath += "_asc";
    std::vector<std::string> ascPaths;
    r.convertToAscii(basePath, ascPaths);
    r.close();
    if (ascPaths.empty()) return 0;
    size_t total = 0;
    AsciiReader ar;
    for (const auto& p : ascPaths) {
        if (ar.open(p)) {
            Frame f;
            while (ar.readFrame(f)) ++total;
            ar.close();
        }
        std::remove(p.c_str());
    }
    return total;
}

static std::string getTempPath(const std::string& base, const std::string& ext) {
    return base + "_test" + ext;
}

int main(int argc, char* argv[]) {
    std::string dataDir = ".";
    if (argc >= 2) dataDir = argv[1];

    std::string mdfPath = dataDir + "/00000012-64BB8F50.MF4";
    std::ifstream check(mdfPath);
    if (!check.good()) {
        std::cerr << "Fichier de test absent: " << mdfPath << std::endl;
        std::cerr << "Placez 00000012-64BB8F50.MF4 dans le repertoire ou passez le chemin en argument." << std::endl;
        return 1;
    }
    check.close();

    std::cout << "Tests de non-regression - flux de conversion" << std::endl;
    std::cout << "Fichier source: " << mdfPath << std::endl;

    ConversionManager cm;
    const std::string baseName = dataDir + "/00000012-64BB8F50";
    const std::string pcapOut = getTempPath(baseName, ".pcap");
    const std::string pcapngOut = getTempPath(baseName, ".pcapng");
    const std::string mdfOut = getTempPath(baseName, ".mf4");
    const std::string asciiOut = getTempPath(baseName, "");

    /* Test 1: MDF -> PCAP (reference pour le nombre de trames) */
    std::cout << "\n[1] MDF -> PCAP" << std::endl;
    bool ok1 = cm.mdfToPcap(mdfPath, pcapOut);
    TEST_ASSERT(ok1, "Conversion MDF->PCAP doit reussir");
    size_t refCount = 0;
    if (ok1) {
        refCount = countFramesInPcap(pcapOut);
        std::cout << "  Reference: " << refCount << " trames" << std::endl;
        TEST_ASSERT(refCount > 0, "MDF->PCAP doit produire des trames");
    }

    /* Test 2: MDF -> PCAPNG */
    std::cout << "\n[2] MDF -> PCAPNG" << std::endl;
    bool ok2 = cm.mdfToPcapng(mdfPath, pcapngOut);
    TEST_ASSERT(ok2, "Conversion MDF->PCAPNG doit reussir");
    if (ok2) {
        size_t n = countFramesInPcapng(pcapngOut);
        TEST_ASSERT(n == refCount, (std::string("MDF->PCAPNG: ") + std::to_string(n) + " trames, attendu " + std::to_string(refCount)).c_str());
    }

    /* Test 3: PCAP -> MDF (round-trip) */
    std::cout << "\n[3] PCAP -> MDF (round-trip)" << std::endl;
    if (ok1) {
        bool ok3 = cm.pcapToMdf(pcapOut, mdfOut);
        TEST_ASSERT(ok3, "Conversion PCAP->MDF doit reussir");
        if (ok3) {
            size_t n = countFramesViaAscii(mdfOut);
            TEST_ASSERT(n == refCount, (std::string("PCAP->MDF: ") + std::to_string(n) + " trames, attendu " + std::to_string(refCount)).c_str());
        }
    }

    /* Test 4: PCAPNG -> MDF (round-trip direct) */
    std::cout << "\n[4] PCAPNG -> MDF (round-trip)" << std::endl;
    std::string mdfOut2 = getTempPath(baseName, "_ng.mf4");
    if (ok2 && refCount > 0) {
        bool ok4 = cm.pcapngToMdf(pcapngOut, mdfOut2);
        TEST_ASSERT(ok4, "Conversion PCAPNG->MDF doit reussir");
        if (ok4) {
            size_t n = countFramesViaAscii(mdfOut2);
            TEST_ASSERT(n == refCount, (std::string("PCAPNG->MDF: ") + std::to_string(n) + " trames, attendu " + std::to_string(refCount)).c_str());
        }
    }

    /* Test 5: MDF -> ASCII -> PCAP (flux complet) */
    std::cout << "\n[5] MDF -> ASCII -> PCAP (flux complet)" << std::endl;
    std::vector<std::string> ascPaths;
    MdfReader reader;
    if (reader.open(mdfPath)) {
        reader.convertToAscii(asciiOut, ascPaths);
        reader.close();
    }
    TEST_ASSERT(!ascPaths.empty(), "MDF->ASCII doit produire des fichiers");
    if (!ascPaths.empty()) {
        AsciiReader ar;
        size_t total = 0;
        for (const auto& p : ascPaths) {
            if (ar.open(p)) {
                Frame f;
                while (ar.readFrame(f)) ++total;
                ar.close();
            }
            std::remove(p.c_str());
        }
        TEST_ASSERT(total == refCount, (std::string("ASCII->comptage: ") + std::to_string(total) + " trames, attendu " + std::to_string(refCount)).c_str());
    }

    /* Nettoyage */
    std::remove(pcapOut.c_str());
    std::remove(pcapngOut.c_str());
    std::remove(mdfOut.c_str());
    std::remove(mdfOut2.c_str());
    std::cout << "\n--- Resultat: " << g_passed << " OK, " << g_failed << " FAIL ---" << std::endl;
    return g_failed > 0 ? 1 : 0;
}
