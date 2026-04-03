# MDF / ASCII / PCAP Converter (pure C++)

**100% C++** with mdflib. **Multi-bus** converter: CAN, CAN FD, LIN, FlexRay, Ethernet.

## Directories

- **MDF**: `D:\yesmine\3eme\PFE\fichiers\mdf`
- **PCAP**: `D:\yesmine\3eme\PFE\fichiers\pcap`
- **Converted files**: `D:\yesmine\3eme\PFE\fichiers\fichiers-convertis` (default when no output path is given)

## Supported bus types

| Bus | MDF -> PCAP | PCAP -> MDF | DLT PCAP |
|-----|-------------|-------------|----------|
| CAN | Yes | Yes | 227 (SocketCAN) |
| CAN FD | Yes | Yes | 227 |
| LIN | Yes | Yes | 254 |
| FlexRay | Yes | Yes | 259 |
| Ethernet | Yes | Yes | 1 |

## MDF -> PCAP / PCAPNG

```powershell
.\build\mdf2ascii.exe --mdf2pcap data.mf4 [output.pcap]
.\build\mdf2ascii.exe --mdf2pcapng data.mf4 [output.pcapng]
.\build\mdf2ascii.exe -m data.mf4 output.pcap
```

The **MDF -> ASCII -> PCAP** path is used: bus groups (CAN, LIN, FlexRay, Ethernet) are converted to ASCII, then written to PCAP/PCAPNG. With mixed frames, one file per type is created (e.g. `output_CAN.pcap`, `output_LIN.pcap`).

## PCAP / PCAPNG -> MDF

```powershell
.\build\mdf2ascii.exe --pcap2mdf capture.pcap [output.mf4]
.\build\mdf2ascii.exe --pcapng2mdf capture.pcapng [output.mf4]
.\build\mdf2ascii.exe -p capture.pcap output.mf4
```

Inverse conversion: frames from PCAP/PCAPNG are written to MDF4 (bus logger format). One MDF file per bus type when several types are present (e.g. `output_CAN.mf4`, `output_LIN.mf4`). Multi-interface PCAPNG (several DLTs) is handled correctly.

## Round-trip verification

```powershell
.\build\mdf2ascii.exe --verify-mdf2pcap data.mf4 output.pcap
.\build\mdf2ascii.exe --verify-pcap2mdf output.pcap output_reconv.mf4
```

## MDF -> ASCII (optional)

```powershell
.\build\mdf2ascii.exe data.mf4 [output]
```

Output: `.asc` files (tab-separated). Useful for manual inspection.

## ASCII -> PCAP / PCAPNG

```powershell
.\build\mdf2ascii.exe --ascii2pcap can_data.asc [output.pcap]
.\build\mdf2ascii.exe --ascii2pcapng can_data.asc [output.pcapng]
.\build\mdf2ascii.exe -a can_data.asc output.pcap
.\build\mdf2ascii.exe -n can_data.asc output.pcapng
```

### Supported ASCII formats

**CAN / LIN / FlexRay** (Timestamp, ID, DLC, Data):

```
Timestamp	ID	DLC	Data
0.001234	0x123	8	11 22 33 44 55 66 77 88
```

**Measurement files** (signals): not convertible to PCAP — explanatory message is shown.

## Build and run

```powershell
# 1. Build (once)
.\build.ps1

# 2. Run without rebuilding
.\run.bat
.\run.bat --mdf2pcap data.mf4
.\run.bat --pcap2mdf capture.pcap

# GUI (Python 3)
.\run_gui.bat
```

**Portable package** (executable without building from source):

```powershell
.\build-dist.ps1
```

Creates the `dist/` folder with `mdf2ascii.exe`, MinGW DLLs, and launch scripts. Copy `dist/` anywhere to use the converter without CMake/vcpkg.

The executable is produced at `build\mdf2ascii.exe` (or `build\Release\mdf2ascii.exe`).

## Project layout

```
converter/
├── main.cpp
├── ConversionManager.h / .cpp
├── bus/                 # BusTypes (Frame, BusType), BusDetector
├── mdf/                 # MdfReader, MdfFrameWriter
├── ascii/               # AsciiReader (uses BusDetector)
├── pcap/                # PcapReader/Writer, PcapNgReader/Writer
├── scripts/             # check_mf4_asammdf.py, mdf2csv_can.py
└── deps/mdflib/
```

## Viewing in asammdf (Bus Trace)

Generated MDF files use **VLSD** (Vector/ASAM compatible) and **SourceInformation** for best compatibility with asammdf.

**To show the bus trace (CAN, LIN, FlexRay, Ethernet):**
1. Open the `.mf4` file
2. Expand channel groups in the tree (left)
3. Select the frame group: `CAN_DataFrame`, `LIN_DataFrame`, `FlexRay_DataFrame`, or `Ethernet_DataFrame`
4. **Create window** -> **CAN/LIN/FlexRay Bus Trace**

If the trace is empty: `python scripts/check_mf4_asammdf.py file.mf4`

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): code and architecture details
- [ANALYSE_ERREURS.md](ANALYSE_ERREURS.md): correction history
