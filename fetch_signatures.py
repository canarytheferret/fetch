import codecs
import os
import re

def load_signatures():
    signatures = {}
    signatures_count = 0
    try:
        signatures_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures')
    except Exception as exception:
        print(f"ERRO: {exception}")
        return {}
    try:
        with open(signatures_file, 'r', encoding='latin1') as file:
            for lines, line in enumerate(file, 1):
                line = line.strip()
                parts = [part.strip() for part in line.split('|')]
                if len(parts) >= 2:
                    signature = parts[0]
                    filetype = parts[1]
                    description = parts[2] if len(parts) > 2 else "Unknown File Type"                
                    try:
                        signbytes = codecs.decode(signature.encode('ascii'), 'unicode_escape').encode('latin1')
                        signatures[signbytes] = (filetype, description)
                        signatures_count += 1
                    except Exception as exception:
                        print(f"WARN: {exception} ({signature})")
                        continue
    except Exception as exception:
        print(f"ERRO: {exception}")
        return {}
    print(f"SUCC: Loaded {signatures_count} Signatures.")
    return signatures
SIGNATURES = load_signatures()