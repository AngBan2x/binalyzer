# binary analyzer

# import local packages
import analyzers
from common import os, sys, struct
import detectors

def help_message(): # for proper use of running the script
    print("Usage: python bin_analyzer.py <path to binary> <arguments>")
    print("Available arguments:")
    print("-h: Help (this same page)")
    print("-a: Analyze")

def analyze_elf(header, file):
    print("It's an ELF binary!")

    # check for the class of the binary
    ei_class = header[4]

    if (ei_class == 1):
        print("Architecture: 32-bit")
    elif(ei_class == 2):
        print("Architecture: 64-bit")
    else:
        print("Error: invalid class. Must be 1 or 2. Returned value:", ei_class)

    #2. Parse the main header: TODO
    
def analyze_pe(header, file):
    print("It's a PE binary!")

    e_lfanew = struct.unpack("<I", header[60:64])[0] # COFF offset
    file.seek(e_lfanew) # go to the offset

    # check for offset validity
    if (file.read(4) == b'PE\0\0'):
        print("COFF offset: Valid at:", e_lfanew)
    else:
        print("COFF offset: INVALID:", e_lfanew)

    #2. Parse the main header: TODO

def main():
    # validate command line arguments
    if (len(sys.argv) != 3 or "-h" in sys.argv or sys.argv[2] != "-a"):
        help_message()
        return

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: couldn't find file {filepath}")
        return
    
    try:
        # open the file in binary mode
        with open(f"{filepath}", "rb") as file:
            # first_64_bytes = struct.unpack("64c", file.read(64)) # read first 64 bytes of the bin
            header = file.read(64)
            
            # 1. validate type of binary
            if (header[:4] == b'\x7FELF'): # if the first 4 bytes are \x7fELF
                analyze_elf(header, file)
            
            elif (header[:2] == b'MZ'): # if the first two bytes are MZ
                analyze_pe(header, file)

            else:
                print("It is neither a ELF nor a PE binary.")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()