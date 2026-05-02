#common/constants.py: constants used all along the project

#ELF related constants ==================================================================
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

E_SHTYPES = { 0: "Null",
             1: "Program information",
             2: "Symbol table",
             3: "String table",
             4: "Relocation (w/ addend)",
             5: "Symbol hash table",
             6: "Dynamic Linking",
             7: "Notes",
             8: "Not present in the file",
             9: "Relocation (no addend)",
             10: "Reserved, no semantics",
             11: "Minimal dynamic linking symbols",
             14: "Array of constructors",
             15: "Array of destructors",
             16: "Array of pre-constructors",
             17: "Section group",
             18: "Extended section indices",
             19: "Relative Relocations",
             20: "Number of defined types",
             0x6ffffff6: "GNU-Style hash table",
             0x6ffffff7: "Prelink library list",
             0x6ffffff8: "Checksum for DSO content",
             # NOT USED: Sun-specific types
             0x6ffffffd: "Version definition section",
             0x6ffffffe: "Version needs section",
             0x6fffffff: "Version symbol table",
}

E_SHFLAGS = { 1 << 0: "Writable",
            1 << 1: "Occupies memory during execution",
            1 << 2: "Executable",
            1 << 4: "Might be merged",
            1 << 5: "Contains null-terminated strings",
            1 << 6: "sh_info contains SHT index",
            1 << 7: "Preserve order while combining",
            1 << 8: "Non-standard OS-specific handling required",
            1 << 9: "Section is member of a group",
            1 << 10: "Section hold thread-local data",
            1 << 11: "Section with compressed data",
            1 << 21: "Not to be GCed by linker"
}

#PE related constants ===================================================================
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

IMAGE_SECTION_CHARACTERISTICS = {0x00000000 : "Reserved for future use",
                                 0x00000001 : "Reserved for future use",
                                 0x00000002 : "Reserved for future use",
                                 0x00000004 : "Reserved for future use",
                                 0x00000008 : "This section should not be padded to the next boundary",
                                 0x00000010 : "Reserved for future use",
                                 0x00000020 : "Contains executable code",
                                 0x00000040 : "Contains initialized data",
                                 0x00000080 : "Contains uninitialized data",
                                 0x00000100 : "Reserved for future use",
                                 0x00000200 : "Contains comments or other information",
                                 0x00000400 : "Reserved for future use",
                                 0x00000800 : "This section will not become part of the image",
                                 0x00001000 : "Contains COMDAT data",
                                 0x00008000 : "Contains data referenced through the global pointer",
                                 0x00020000 : "Reserved for future use",
                                 0x00040000 : "Reserved for future use",
                                 0x00080000 : "Reserved for future use",
                                 0x00100000 : "1-byte boundary data alignment",
                                 0x00200000 : "2-byte boundary data alignment",
                                 0x00300000 : "4-byte boundary data alignment",
                                 0x00400000 : "8-byte boundary data alignment",
                                 0x00500000 : "16-byte boundary data alignment",
                                 0x00600000 : "32-byte boundary data alignment",
                                 0x00700000 : "64-byte boundary data alignment",
                                 0x00800000 : "128-byte boundary data alignment",
                                 0x00900000 : "256-byte boundary data alignment",
                                 0x00A00000 : "512-byte boundary data alignment",
                                 0x00B00000 : "1024-byte boundary data alignment",
                                 0x00C00000 : "2048-byte boundary data alignment",
                                 0x00D00000 : "4096-byte boundary data alignment",
                                 0x00E00000 : "8192-byte boundary data alignment",
                                 0x01000000 : "Contains extended relocations",
                                 0x02000000 : "Discardable section",
                                 0x04000000 : "Not cacheable",
                                 0x08000000 : "Not pageable",
                                 0x10000000 : "Can be shared in memory",
                                 0x20000000 : "Can be executed as code",
                                 0x40000000 : "Can be read",
                                 0x80000000 : "Can be written to",
}

OPTIONAL_MAGIC = {0x10b : "PE32", 0x20b : "PE32+"}