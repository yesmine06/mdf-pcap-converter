#pragma once

#include "BusTypes.h"
#include <string>
#include <vector>

/**
 * BusDetector - Detecte le type de bus et si une ligne est une trame convertible.
 * Analyse les lignes ASCII ou les en-tetes MDF pour distinguer:
 * - Trame bus (CAN, LIN, FlexRay, Ethernet) -> convertible PCAP
 * - Signal physique continu -> non convertible
 */
class BusDetector {
public:
    BusDetector() = default;

    /**
     * Analyse une ligne et detecte si c'est une trame bus.
     * Appeler feedHeader() avant pour les fichiers avec en-tete.
     * @param parts Colonnes de la ligne (deja splittee)
     * @param busType [out] Type de bus detecte
     * @param frame [out] Trame parsee si conversion reussie
     * @return true si trame convertible, false si signal ou ligne invalide
     */
    bool isBusFrame(const std::vector<std::string>& parts, BusType& busType, Frame& frame);

    /**
     * Envoie une ligne d'en-tete pour detection du format.
     * @return true si format trame detecte, false si fichier de mesures
     */
    bool feedHeader(const std::vector<std::string>& headers);

    /**
     * Indique si le format actuel est une trame bus (vs signaux).
     */
    bool isFrameFormat() const { return formatDetected_ && busType_ != BusType::Unknown; }

    BusType detectedBusType() const { return busType_; }

    /**
     * Indique si le type de bus est convertible en PCAP.
     */
    static bool isConvertibleToPcap(BusType bus);

private:
    bool formatDetected_ = false;
    BusType busType_ = BusType::Unknown;
    int colTime_ = 0, colId_ = 1, colDlc_ = 2, colData_ = 3;
};
