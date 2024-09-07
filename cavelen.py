import pefile
import sys

'''
Utility script to check the code cave length of the specified PE.
Usage:
    python cavelen.py PE_FILE
'''


def find_code_cave_len(pe: pefile.PE):
    raw_end = pe.sections[0].PointerToRawData + \
        pe.sections[0].SizeOfRawData - 1
    raw_start = raw_end
    while pe.get_word_from_offset(raw_start) & 0xff == 0:
        raw_start -= 1
    raw_start += 1
    return raw_end - raw_start

pe = pefile.PE(sys.argv[1], fast_load=False)
cave_len = find_code_cave_len(pe)
print(f'Code cave len: {cave_len}')