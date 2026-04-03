#!/usr/bin/env python3
"""Diagnostic: ce qu'asammdf lit dans un fichier MF4 (bus trace, timestamps)."""
import sys
import os

# Ajouter le chemin si asammdf n'est pas installé globalement
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    mf4_path = sys.argv[1] if len(sys.argv) > 1 else None
    if not mf4_path:
        # Essayer le fichier du projet
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "00000012-64BB8F50.MF4"),
            r"D:\yesmine\3eme\PFE\fichiers\fichiers-convertis\00000012-64BB8F50.mf4",
        ]
        for p in candidates:
            if os.path.isfile(p):
                mf4_path = p
                break
        if not mf4_path:
            print("Usage: python check_mf4_asammdf.py <fichier.mf4>")
            print("  ou placez 00000012-64BB8F50.MF4 dans le dossier du projet")
            return 1

    if not os.path.isfile(mf4_path):
        print(f"Fichier non trouvé: {mf4_path}")
        return 1

    try:
        from asammdf import MDF
    except ImportError:
        print("asammdf non installé. pip install asammdf")
        return 1

    print(f"=== Diagnostic: {mf4_path} ===\n")

    mdf = MDF(mf4_path)
    print("=== Structure MDF ===")
    print(f"Version: {mdf.version}")
    print(f"Groupes de canaux (channel groups):")
    for i, name in enumerate(mdf.channels_db):
        print(f"  {i}: {name}")
    print()

    # Lecture CAN_DataFrame (group/index si multiples occurrences)
    sig = None
    try:
        sig = mdf.get("CAN_DataFrame", group=0, index=1)
    except Exception:
        try:
            sig = mdf.get("CAN_DataFrame")
        except Exception:
            pass
    if sig is not None:
        print("=== CAN_DataFrame ===")
        print(f"  samples: {len(sig)}")
        if len(sig) > 0:
            ts = sig.timestamps
            non_mono = sum(1 for i in range(1, len(ts)) if ts[i] <= ts[i-1])
            if non_mono > 0:
                print(f"  ATTENTION: {non_mono} timestamps non monotones -> vue bus trace peut être vide")
            else:
                print(f"  Timestamps: OK (monotones)")

    # Vérifier si bus logging est détecté
    print("\n=== Bus logging (GUI) ===")
    print("Pour afficher la vue bus trace:")
    print("  1. Cochez 'CG 0 CAN_DataFrame' (ou le groupe CAN)")
    print("  2. Cliquez sur le bouton 'Create window' (ou F2/F3/F4)")
    print("  3. Choisissez 'CAN Bus Trace' (pas Plot/Tabular)")
    print("  4. Cliquez Apply")
    print("\nSi la vue reste vide: régénérez le MDF avec mdf2ascii --pcap2mdf")

    mdf.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
