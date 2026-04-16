# analyzers/elf_analyzer.py: module that analyzes ELF binaries
import struct
from common import constants as c
from common import helpers as h

def unpack_header(header=str(None)) -> tuple:
    """
    Unpacks the header based on the data endianness and the architechture.
    
    Args:
        header(str): The header of the file, read previously as a string of binary bytes. Must be provided

    Returns:
        unpacked_header(tuple): A struct that contains all of the information of the header in an organized matter.

    Raises:
        ValueError: If the header isn't provided
    """

    if header == None or len(header) < 64:
        raise ValueError("Error: header empty, not provided or invalid size")
    else:
        architecture = header[4]
        endianness = header[5]
        unpacked_header = tuple()

        if(architecture == 1 and endianness == 1): # 32-bit, little endian
            unpacked_header = struct.unpack("<16BHHIIIIIHHHHHH", header[:52]) # 32-bit ELF headers are 52 bytes in size
        elif(architecture == 1 and endianness == 2): # 32-bit, big endian
            unpacked_header = struct.unpack(">16BHHIIIIIHHHHHH", header[:52])
        elif(architecture == 2 and endianness == 1): # 64-bit, little endian
            unpacked_header = struct.unpack("<16BHHIQQQIHHHHHH", header)
        elif(architecture == 2 and endianness == 2): # 64-bit, big endian
            unpacked_header = struct.unpack(">16BHHIQQQIHHHHHH", header)
        else:
            raise ValueError("Error: Invalid architecture or data endianness\nArchitecture value:", architecture,
                             "\nData endianness:", endianness)

        return unpacked_header

def section_type(value: int) -> str:
    """
    Detects the type of the section, given a value

    Args:
        value(int)
    Returns:
        result(str): Can be a string that describes the type or a hex value if not found
    """

    result = str()
    type = c.E_SHTYPES.get(value)
    if type is None:
        if value >= 0x60000000 and value <= 0x6ffffff5:
            type = "OS-Specific"
        elif value >= 0x70000000 and value <= 0x7fffffff:
            type = "Processor-specific"
        elif value >= 0x80000000 and value <= 0x8fffffff:
            type = "User application-specific"
        else:
            type = str(hex(value))

    result = type
    return result

def section_flags(value: int) -> dict:
    """
    Detects the bit flags within a given value and returns a dictionary with given information 
    
    Args:
        value(int)
    
    Returns:
        flags(dict): Dictionary containing information of available flags. If none are available, then it will be defined as {0x0: None}
    """

    flags = dict()
    
    if value == 0:
        flags[0x0] = "None"
    elif (value >= 0x0ff00000):
        flags[0x0ff00000] = "OS-specific"
        if (value >= 0xf0000000):
            flags[0xf0000000] = "Processor-specific"
    elif value not in c.E_SHFLAGS.keys():
        flags[hex(value)] = "Other"
    else:
        aux = value
        i = 0
        while (aux > 0):
            digit = ((aux % 2) << i)
            if digit in c.E_SHFLAGS.keys():
                flags[hex(digit)] = c.E_SHFLAGS[digit]

            aux = aux // 2
            i += 1

    return flags

def parse_elf_header(header, file=None):
    """
    Parses the ELF header and extracts all of the relevant information, like architecture.

    Args:
        header(str): String in binary bytes
        file(__file__): filetype object to read from

    Returns:
        header_info(dict): a dictionary containing all of the relevant information from the header

    Raises:
        ValueError: if file is not provided
    """

    if file is None:
        raise ValueError("Error: non-empty file object must be provided")

    header_info = dict() # organized and "tagged" ELFN_Ehdr

    # ----------------ELFN_Ehdr----------------------
    ELFN_Ehdr = unpack_header(header) # unpacked header
    e_ident = dict()
    e_ident["Magic number"] = str(hex(ELFN_Ehdr[0])) + chr(ELFN_Ehdr[1]) + chr(ELFN_Ehdr[2]) + chr(ELFN_Ehdr[3])
    e_ident["Class (architecture)"] = c.EI_CLASS.get(ELFN_Ehdr[4])
    e_ident["Data encoding"] = "Two's complement, " + c.EI_DATA.get(ELFN_Ehdr[5])
    e_ident["Version"] = ELFN_Ehdr[6]
    e_ident["OS/ABI target"] = c.EI_OSABI.get(ELFN_Ehdr[7]) + " ABI"
    e_ident["ABI version"] = ELFN_Ehdr[8]

    header_info["e_ident (Identification)"] = e_ident
    header_info["e_type (Object file type)"] = c.E_TYPE.get(ELFN_Ehdr[16]) # skip to index 16; the rest is padding

    e_machine = c.E_MACHINE.get(ELFN_Ehdr[17])
    if (e_machine == None):
        header_info["e_machine (Required architecture)"] = "Other"
    else:
        header_info["e_machine (Required architecture)"] = e_machine

    header_info["e_version (File version)"] = ELFN_Ehdr[18]
    header_info["e_entry (Point of entry)"] = hex(ELFN_Ehdr[19])
    header_info["e_phoff (Program Header Table offset)"] = ELFN_Ehdr[20]
    header_info["e_shoff (Section Header Table offset)"] = ELFN_Ehdr[21]
    header_info["e_flags (Processor Specific Flags)"] = ELFN_Ehdr[22]
    header_info["e_ehsize (Header size)"] = ELFN_Ehdr[23]
    header_info["e_phentsize (Program Header Table entry size)"] = ELFN_Ehdr[24]
    header_info["e_phnum (Program Header Table entries)"] = ELFN_Ehdr[25]
    header_info["e_shentsize (Section Header Table entry size)"] = ELFN_Ehdr[26]
    header_info["e_shnum (Section Header Table entries)"] = ELFN_Ehdr[27]
    header_info["e_shstrndx (Section Header String Table Index)"] = ELFN_Ehdr[28]

    return header_info

def list_sections(header=dict(), file=None) -> list:
    if file is None:
        raise ValueError("Error: non-empty file object must be provided")
    elif header is None:
        raise ValueError("Error: non-empty header must be provided")
    else:
        section_list = list() # list with results

        # Get architecture and endianness formats from the header for proper reading/unpacking
        architecture = header.get("e_ident (Identification)").get("Class (architecture)")
        af = "I" if "32" in architecture else "Q" # architecture format, either uint or ulonglong
        endianness = header.get("e_ident (Identification)").get("Data encoding")
        ef = "<" if "Little" in endianness else ">" # endianness format, either little or big

        sh_off = header.get("e_shoff (Section Header Table offset)")
        sh_entsize = header.get("e_shentsize (Section Header Table entry size)")
        sh_num = header.get("e_shnum (Section Header Table entries)")

        file.seek(sh_off)

        for i in range(sh_num):
            section = dict()
            raw_shdr = file.read(sh_entsize)
            unp_shdr = struct.unpack(f"{ef}II{af}{af}{af}{af}II{af}{af}", raw_shdr)
            section["Name"] = unp_shdr[0]
            section["Type"] = section_type(unp_shdr[1])
            section["Flags"] = section_flags(unp_shdr[2])
            section["Address"] = hex(unp_shdr[3])
            section["Offset"] = unp_shdr[4]
            section["Size"] = unp_shdr[5]
            section["Link"] = unp_shdr[6]
            section["Info"] = unp_shdr[7]
            section["Address alignment"] = unp_shdr[8]
            section["Entry size"] = unp_shdr[9]
            section_list.append(section)

        # Get section header string table index
        shstrndx = header["e_shstrndx (Section Header String Table Index)"]
        str_section = section_list[shstrndx]
        # Read the string table through its "Size" field
        file.seek(str_section["Offset"])
        string_table = file.read(str_section["Size"])

        # get a name given an offset
        def get_name(offset):
            if offset == 0:
                return "None"
            # read until the first null byte and slice to return
            end = string_table.find(b'\x00', offset)
            return string_table[offset:end].decode('utf-8')

        # add the proper names of the sections
        for sec in section_list:
            sec["Name"] = get_name(sec["Name"])

        return section_list


def extract_strings(file=__file__): # TODO
    raise NotImplementedError

def analyze(header, file=None) -> dict:
    """
    Analyzes the entirety of the file.

    Args:
        header(str): Header of the file; a string of binary bytes 
        file(__file__): Given file to analyze. Needed for additional reading beyond the header

    Returns:
        info(dict): Contains all information related to the binary.

    Raises:
        ValueError: If the file isn't provided or is empty
    """
    if file is None:
        raise ValueError("error: file object must be provided")
    else:
        info = dict()
        info["Header"] = parse_elf_header(header, file)
        info["Sections"] = list_sections(info["Header"], file)
        # info["Strings"] = extract_strings(file)
        return info