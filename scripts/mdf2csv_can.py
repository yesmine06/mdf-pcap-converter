#!/usr/bin/env python3
"""Exporte les trames CAN d'un fichier MDF vers CSV (pour Excel ou autre)."""
import sys
import csv
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: python mdf2csv_can.py <file.mf4> [output.csv]")
        return 1

    mf4_path = sys.argv[1]
    csv_path = sys.argv[2] if len(sys.argv) > 2 else mf4_path.replace(".mf4", ".csv").replace(".mdf", ".csv")

    if not os.path.isfile(mf4_path):
        print(f"Fichier non trouvé: {mf4_path}")
        return 1

    try:
        from asammdf import MDF
    except ImportError:
        print("asammdf requis: pip install asammdf")
        return 1

    mdf = MDF(mf4_path)

    try:
        ts = mdf.get("t")
        if ts is None:
            ts = mdf.get("CAN_DataFrame")
        if ts is None:
            print("Aucun canal de timestamp trouvé.")
            return 1

        ids = mdf.get("CAN_DataFrame.ID")
        dlcs = mdf.get("CAN_DataFrame.DLC")
        data = mdf.get("CAN_DataFrame.DataBytes")

        if ids is None or data is None:
            print("Canaux CAN_DataFrame non trouvés.")
            return 1

        n = len(ids)
        if n == 0:
            print("Aucune trame.")
            return 1

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Timestamp", "ID", "DLC", "DataBytes"])
            for i in range(n):
                t = ts.timestamps[i] if ts is not None else i
                id_val = int(ids.samples[i]) if ids is not None else 0
                id_val &= 0x1FFFFFFF  # CAN 29-bit
                dlc_val = int(dlcs.samples[i]) if dlcs is not None else 0
                data_bytes = data.samples[i]
                if hasattr(data_bytes, "tobytes"):
                    data_bytes = data_bytes.tobytes()
                hex_str = " ".join(f"{b:02X}" for b in data_bytes[:dlc_val]) if dlc_val else ""
                w.writerow([t, f"0x{id_val:X}", dlc_val, hex_str])

        print(f"Exporté: {n} trames -> {csv_path}")
    finally:
        mdf.close()

    return 0

if __name__ == "__main__":
    sys.exit(main())
