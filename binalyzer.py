# binary analyzer
import os
import struct
import sys

def help_message(): # for proper use of running the script
    print("Usage: python bin_analyzer.py <path to binary> <arguments>")
    print("Available arguments:")
    print("-h: Help (this same page)")
    print("-a: Analyze")

# validate command line arguments
if (len(sys.argv) != 3 or "-h" in sys.argv):
    help_message()
elif(len(sys.argv) == 3 and sys.argv[2] == "-a"):
    
    # open the file in binary mode
    with open(f"{sys.argv[1]}", "rb") as file:
        first_64_bytes = struct.unpack("64c", file.read(64)) # read first 64 bytes of the bin
        # print("first 64 bytes:", first_64_bytes)
        
        # 1. validate type of binary
        if (first_64_bytes[:4] == (b'\x7F', b'E', b'L', b'F')): # if the first 4 bytes are \x7fELF
            print("It's an ELF binary!")

            # check for the class of the binary
            ei_class = struct.unpack("b", first_64_bytes[4])[0]

            if (ei_class == 1):
                print("Its architecture is 32-bit")
            elif(ei_class == 2):
                print("Its architecture is 64-bit")
            else:
                print("Error: invalid class. Must be 1 or 2. Returned value:", ei_class)

            #2. Parse the main header: TODO
        
        elif (first_64_bytes[:2] == (b'M', b'Z')): # if the first two bytes are MZ
            print("It's a PE binary!")

            e_lfanew = struct.unpack("4b", first_64_bytes[60:63]) # COFF offset

            # check for offset validity
            if (e_lfanew == (b'PE\0\0')):
                print("COFF offset: Valid")
            else:
                print("COFF offset: INVALID:", e_lfanew)

        else:
            print("It is neither a ELF nor a PE binary.")

        file.close()

else:
    help_message()
