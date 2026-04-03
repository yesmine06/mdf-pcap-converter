# Analyse des erreurs du projet Converter

Document genere a partir de l'analyse complete du projet. Toutes les erreurs identifiees ont ete corrigees.

**Derniere mise a jour** : Support multi-bus complet (CAN, LIN, FlexRay, Ethernet) pour MDF↔PCAP/PCAPNG. MdfFrameWriter utilise le CG adapte par type. PcapNgReader gere les fichiers multi-interfaces.

---

## 1. Erreurs critiques (corrigées)

### 1.1 PcapNgReader – CAN FD tronqué ✅ CORRIGÉ
- **Fichier** : `pcap/PcapNgReader.cpp` ligne 111
- **Problème** : `if (dlc > 8) dlc = 8` limitait à 8 octets alors que CAN FD peut aller jusqu'à 64.
- **Correction** : `if (dlc > 64) dlc = 64` pour supporter CAN FD.

### 1.2 ConversionManager – Échec ar.open silencieux ✅ CORRIGÉ
- **Fichier** : `ConversionManager.cpp` (4 occurrences)
- **Problème** : `if (!ar.open(ascPath)) continue;` ignorait les échecs sans message.
- **Correction** : Ajout de `std::cerr << "Warning: cannot open ASCII file: " << ascPath << std::endl;`

---

## 2. Erreurs moyennes (corrigées)

### 2.1 MdfFrameWriter – Tous types de bus supportes ✅ CORRIGÉ
- **Correction** : CAN, LIN, FlexRay et Ethernet utilisent chacun leur ChannelGroup : `CAN_DataFrame`, `LIN_DataFrame`, `FlexRay_DataFrame`, `Ethernet_DataFrame`. mdflib `CreateBusLogConfiguration()` cree le bon CG selon `BusType`. Format VLSD + SourceInformation pour compatibilite asammdf.

### 2.2 ConversionManager – Offset timestamp arbitraire ✅ CORRIGÉ
- **Correction** : Utilisation de l'heure système actuelle (`std::chrono::system_clock::now()`) au lieu d'une date fixe 2024-01-01.

### 2.3 PcapWriter – Résolution microsecondes ✅ CORRIGÉ
- **Correction** : Paramètre `useNanoseconds` ajouté à `PcapWriter::open()`. Support du format PCAP nanosecondes (magic `0xa1b23c4d`).

### 2.4 main.cpp – Chemin de sortie codé en dur ✅ CORRIGÉ
- **Correction** : Variable d'environnement `CONVERTER_OUTPUT_DIR` pour configurer le répertoire de sortie.

---

## 3. Risques potentiels (corrigés)

### 3.1 MdfReader – Logique stem ✅ CORRIGÉ
- **Correction** : Détection du dernier point après le dernier séparateur de chemin (`lastDot > lastSep`).

### 3.2 ConversionManager – Pas de close explicite en cas d'échec ✅ CORRIGÉ
- **Correction** : Appel à `writer.close()` avant `return false` en cas d'échec de `writeFrames`.

### 3.3 PcapNgReader – Multi-interfaces ✅ CORRIGÉ
- **Correction** : Map `interfaceToDlt_` pour associer chaque EPB au DLT de son interface. Reset a chaque SHB (nouvelle section). Support CAN, LIN, FlexRay, Ethernet.

### 3.4 std::remove sans vérification ✅ CORRIGÉ
- **Correction** : Fonction `removeFile()` qui vérifie le code de retour et affiche un avertissement en cas d'échec.

### 3.5 BusDetector – atoi/atof sans validation ✅ CORRIGÉ
- **Correction** : Utilisation de `strtod` et `strtol` avec vérification du pointeur `end` et des plages.

---

## 4. Flux de conversion

| Flux | Implémentation | Notes |
|------|----------------|------|
| MDF → PCAP | MDF → ASCII → PCAP | Fichiers ASCII temporaires supprimés |
| MDF → PCAPNG | MDF → ASCII → PCAPNG | Idem |
| PCAP → MDF | Direct | Timestamps : offset si < 86400 s |
| PCAPNG → MDF | Direct | Idem |
| ASCII → PCAP/PCAPNG | Direct | Writer ouvert à la 1ère trame |

---

## 5. Structure du projet

```
converter/
├── main.cpp                 # Point d'entrée CLI
├── ConversionManager.cpp/h  # Orchestrateur
├── mdf/                     # MdfReader, MdfFrameWriter
├── pcap/                    # PcapReader/Writer, PcapNgReader/Writer
├── ascii/                   # AsciiReader
├── bus/                     # BusTypes, BusDetector
├── tests/run_tests.cpp      # Tests de non-régression
└── deps/mdflib/             # Bibliothèque MDF ASAM
```

---

## 6. Priorites de correction

| Priorite | Action |
|----------|--------|
| Haute | ✅ PcapNgReader CAN FD |
| Haute | ✅ ConversionManager ar.open |
| Moyenne | ✅ MdfFrameWriter : support LIN/FlexRay/Ethernet (CG dynamique) |
| Moyenne | ✅ PcapNgReader : multi-interfaces |
| Basse | ✅ main.cpp : OUTPUT_DIR configurable (CONVERTER_OUTPUT_DIR) |
| Basse | ✅ PcapWriter : option nanosecondes |
