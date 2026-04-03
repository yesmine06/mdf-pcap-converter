#!/usr/bin/env python3
"""
Script pour vérifier qu'un MDF peut être lu par asammdf et afficher les infos bus logging.
Usage: python check_mdf_asammdf.py <fichier.mf4>
"""
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_mdf_asammdf.py <fichier.mf4>")
        sys.exit(1)
    
    path = sys.argv[1]
    try:
        from asammdf import MDF
    except ImportError:
        print("Installez asammdf: pip install asammdf[gui]")
        sys.exit(1)
    
    print(f"Ouverture de {path}...")
    with MDF(path) as mdf:
        print(f"  Version MDF: {mdf.version}")
        print(f"  Nombre de groupes: {len(mdf.groups)}")
        
        for i, grp in enumerate(mdf.groups):
            if grp.channel_group:
                cg = grp.channel_group
                name = getattr(cg, 'acq_name', None) or getattr(cg, 'name', f'CG{i}')
                flags = getattr(cg, 'flags', 0)
                # BusEvent = 0x0002, PlainBusEvent = 0x0004
                is_bus = (flags & 0x0006) != 0 if hasattr(flags, '__and__') else False
                samples = getattr(cg, 'cycles_nr', 0) or 0
                print(f"  Groupe {i}: {name} (bus={is_bus}, samples={samples})")
        
        # Essayer d'extraire les canaux bus
        ch_names = list(mdf.channels_db.keys())
        bus_ch = [c for c in ch_names if 'CAN' in c or 'DataFrame' in c or 'ID' in c]
        if bus_ch:
            print(f"  Canaux bus trouvés: {bus_ch[:10]}{'...' if len(bus_ch) > 10 else ''}")
        
        # Test get pour un canal
        try:
            sigs = [c for c in ch_names if 'CAN_DataFrame' in c and 'ID' in c]
            if sigs:
                s = mdf.get(sigs[0])
                if s is not None:
                    print(f"  Signal {sigs[0]}: {len(s.samples)} échantillons")
        except Exception as e:
            print(f"  Erreur lecture signal: {e}")
    
    print("OK - Fichier lisible par asammdf.")

if __name__ == "__main__":
    main()
