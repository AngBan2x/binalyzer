# analyzers/elf_analyzer.py: module that analyzes ELF binaries
import struct
from common import constants as c

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

    if header == None:
        raise ValueError("Error: header empty or not provided")
    else:
        architecture = header[6]
        endianness = header[5]
        unpacked_header = tuple()

        if(architecture == 1 and endianness == 1): # 32-bit, little endian
            unpacked_header = struct.unpack("<16BHHIIIIIHHHHHH", header[:52]) # 32-bit ELF headers are 52 bytes in size
        elif(architecture == 1 and endianness == 2): # 32-bit, big endian
            unpacked_header = struct.unpack(">16BHHIIIIIHHHHHH", header[:52])
        elif(architecture == 2 and endianness == 1): # 64-bit, little endian
            unpacked_header = struct.unpack("<16BHHIQQQIHHHHHH", header)
        elif(architecture == 2 and endianness == 2): # 64-bit, big endian
            unpacked_header = struct.unpack("<16BHHIQQQIHHHHHH", header)
        else:
            raise ValueError("Error: Invalid architecture or data endianness\nArchitecture value:", architecture,
                             "\nData endianness:", endianness)

        return unpacked_header

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
        raise ValueError("error: file object must be provided")

    header_info = dict() # organized and "tagged" ELFN_Ehdr

    # ----------------ELFN_Ehdr----------------------
    ELFN_Ehdr = unpack_header(header) # unpacked header
    print(ELFN_Ehdr)
    e_ident = dict()
    e_ident["Magic number"] = str(hex(ELFN_Ehdr[0])) + chr(ELFN_Ehdr[1]) + chr(ELFN_Ehdr[2]) + chr(ELFN_Ehdr[3])
    e_ident["Class (architecture)"] = c.EI_CLASS.get(ELFN_Ehdr[4])
    e_ident["Data encoding"] = "Two's complement, " + c.EI_DATA.get(ELFN_Ehdr[5])
    e_ident["Version"] = ELFN_Ehdr[6]
    e_ident["OS/ABI target"] = c.EI_OSABI.get(ELFN_Ehdr[7]) + " ABI"
    e_ident["ABI version"] = ELFN_Ehdr[8]

    header_info["e_ident (Identification)"] = e_ident
    header_info["e_type (Object file type)"] = c.E_TYPE.get(ELFN_Ehdr[16]) # skip to index 16 because the rest is padding

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


def list_sections(file=__file__):
    raise NotImplementedError

def extract_strings(file=__file__):
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
        # info["Sections"] = list_sections(file)
        # info["Strings"] = extract_strings(file)
        return info