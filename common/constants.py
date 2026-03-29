#common/constants.py: constants used all along the project

#ELF related constants
ELF_MAG0_3 = b'\x7fELF' # the magic number (bytes 0 to 3) of the ELF Header

#PE related constants
PE_HEADER = b'MZ'
PE_SIGNATURE = b'PE\0\0'
IMAGE_FILE_MACHINES = {"x64" : 0x8664,
                       "i386" : 0x14c,
                       "Any" : 0x0}

IMAGE_FILE_CHARACTERISTICS = {"Does not contain base relocations" : 0x0001,
                              "Executable file": 0x0002,
                              "Line numbers removed": 0x0004,
                              "Local symbols removed": 0x0008,
                              "Obsolete": 0x0010,
                              "Can handle >2GB addresses": 0x0020,
                              "Reserved for future use": 0x0040,
                              "Bytes in little endian": 0x0080,
                              "Machine is 32-bit": 0x0100,
                              "Debug info removed": 0x0200,
                              "On removable media": 0x0400,
                              "On network media": 0x800,
                              "System file (not user program)": 0x1000,
                              "This is a DLL": 0x2000,
                              "Must be run ONLY on a uniprocessor machine": 0x4000,
                              "Bytes in big endian": 0x8000}