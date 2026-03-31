#common/constants.py: constants used all along the project

#ELF related constants
ELF_MAG0_3 = b'\x7fELF' # the magic number (bytes 0 to 3) of the ELF Header
EI_CLASS = {1 : "32-bit",
            2 : "64-bit"} # class (architecture) of the ELF
EI_DATA = {1: "Little Endian",
           2: "Big Endian"} # data endianness
EI_OSABI = {0: "UNIX System V",
            1: "HP-UX",
            2: "NetBSD",
            3: "Linux",
            4: "Solaris",
            5: "IRIX",
            6: "FreeBSD",
            7: "TRU64 UNIX",
            8: "ARM architecture",
            9: "Stand-alone (embedded)"}
E_TYPE = {0: "Unknown",
          1: "REL (Relocatable file)",
          2: "EXEC (Executable file)",
          3: "DYN (Shared object)",
          4: "CORE (Core file)"}

E_MACHINE = {0: "Unknown",
            3: "x86 (Intel 386)",
            0x3E: "AMD x86-64",
            0x28: "ARM 32-bit",
            0xB7: "AArch64 (ARM 64-bit)"}

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

OPTIONAL_MAGIC = {0x10b : "PE32", 0x20b : "PE32+"}