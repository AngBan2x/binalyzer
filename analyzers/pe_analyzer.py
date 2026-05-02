import struct
from common import constants as c
from datetime import datetime, timezone

def pe_machine_type(machine=int) -> str:
    """
    Specifies the CPU type of the binary

    Args:
        machine(int): taken from the Machine field of the PE Header File Header
        
    Returns:
        result(str): a string indicating the CPU type that is compatible for running the current binary
    """

    result = "Other (unknown)"

    for key, value in c.IMAGE_FILE_MACHINES.items():
        if machine == value:
            result = key
            break

    return result

def get_flags(characteristics=int, av_flags=dict) -> dict:
    """
    Indicates information about the characteristics of a certain aspect of the PE file
    
    Args:
        characteristics(int): Taken from the Characteristics field from a PE Header. Contains flags to be extracted in hex
        ref_flags(dict): Dictionary of available flags of a certain aspect of the binary, taken from common/constants.py

    Returns:
        flags(dict): A dictionary that contains attributes of the object or image file. Follows the format: {flag_description: flag_hex_value, ...}
    """

    flags = dict() # resulting dictionary to be returned

    for key in av_flags.keys():
        if characteristics & key == key:
            flags[hex(key)] = av_flags[key]

    return flags

def parse_dos_header(file=None):
    """DOS Header Parser"""
    if file is None:
        raise ValueError("error: file object must be provided")

def parse_pe_header(header=str, file=None) -> dict:
    """
    Parses the PE header of the binary and returns a dictionary with all of its information

    Args:
        header(str): The first 52 or 64 bytes of the binary, depending on the architecture. Cannot be empty.
        file(__file__): File object, for additional reading of the file. Must be provided/non-empty.
    
    Returns:
        pe_header_info(dict): A dictionary containing all of the information related to the PE Header.

    Raises:
        ValueError: If the file object is empty or not provided
    """
    if file is None:
        raise ValueError("error: file object must be provided")
    else:
        pe_header_info = dict()
        e_lfanew = struct.unpack("<I", header[60:64])[0] # COFF offset
        pe_header_info["COFF Offset"] = e_lfanew
        file.seek(e_lfanew) # go to the offset
        pe_signature = file.read(4)
        pe_header_info["Signature"] = pe_signature

        # ---------------------Read File Header----------------------
        header_info = struct.unpack("<HHIIIHH", file.read(20))
        file_header = dict()

        file_header["Machine"] = pe_machine_type(header_info[0])
        file_header["NumberOfSections"] = header_info[1]
        file_header["TimeDateStamp"] = datetime.fromtimestamp(header_info[2], tz=timezone.utc)
        file_header["PointerToSymbolTable"] = header_info[3]
        file_header["NumberOfSymbols"] = header_info[4]
        file_header["SizeOfOptionalHeader (bytes)"] = header_info[5]
        file_header["Characteristics"] = get_flags(header_info[6], c.IMAGE_FILE_CHARACTERISTICS)

        pe_header_info["File Header"] = file_header

        #-----------------------Read optional header----------------------
        header_info = struct.unpack("<HBBIIIII", file.read(24))

        optional_header = dict()
        opt_standard = dict() # optional standard fields
        print("Magic number", hex(header_info[0]))
        opt_standard["Magic"] = c.OPTIONAL_MAGIC.get(header_info[0])
        opt_standard["MajorLinkerVersion"] = header_info[1]
        opt_standard["MinorLinkerVersion"] = header_info[2]
        opt_standard["SizeOfCode"] = header_info[3]
        opt_standard["SizeOfInitializedData"] = header_info[4]
        opt_standard["SizeOfUnitizializedData"] = header_info[5]
        opt_standard["AddressOfEntryPoint"] = header_info[6]
        opt_standard["BaseOfCode (address)"] = header_info[7]

        if opt_standard["Magic"] == "PE32":
            opt_standard["BaseOfData (address)"] = struct.unpack("<I", file.read(4))[0] # PE32 exclusive

        optional_header["Standard Fields"] = opt_standard

        pe_header_info["Optional Header"] = optional_header

        return pe_header_info

def list_sections(header=dict(), file=None):
    """
    Parses through each section of the binary and returns a list that contains information of each one

    Args:
        header(dict): The PE header, required to be able to be able to get the offset for reading the Sections. Must be provided and non-empty
        file(__file__): File object, required to read each entry from the Section Header Table. Must be provided and non-empty
    
    Returns:
        section_list(list): A list of dictionaries, where each dictionary represents the struct that holds all of the information related to the section

    Raises:
        ValueError: When either the header or the file object is empty or isn't provided.
    """
    if file is None:
        raise ValueError("error: non-empty file object must be provided")
    elif header is None:
        raise ValueError("error: non-empty header must be provided")

    def get_name(name=str) -> str:
        """Get the decoded name off of a string of bytes"""
        # conditional to avoid errors while I figure out how to properly extract the name
        if b'/' in name:
            return name # TODO : extract the name properly from the string table
        else:
            name = name.replace(b'\x00', b'') # Delete all null bytes
            return name.decode('utf-8', errors="replace") # Error handling if necessary
            
    num_sections = header["File Header"]["NumberOfSections"]

    # section table offset: COFF Offset value, 4 for signature, 20 for coff file header + SizeOfOptionalHeader
    st_off = header["COFF Offset"] + 4 + 20 + header["File Header"]["SizeOfOptionalHeader (bytes)"] # section table offset
    file.seek(st_off, 0)
    
    section_list = list()
    for i in range(num_sections):
        section = dict()
        section["Name"] = get_name(struct.unpack("<8s", file.read(8))[0])
        section["VirtualSize"] = hex(struct.unpack("<I", file.read(4))[0])
        section["VirtualAddress"] = hex(struct.unpack("<I", file.read(4))[0])
        section["SizeOfRawData"] = hex(struct.unpack("<I", file.read(4))[0])
        section["PointerToRawData"] = hex(struct.unpack("<I", file.read(4))[0])
        section["PointerToRelocations"] = hex(struct.unpack("<I", file.read(4))[0])
        section["PointerToLinenumbers"] = hex(struct.unpack("<I", file.read(4))[0])
        section["NumberOfRelocations"] = hex(struct.unpack("<H", file.read(2))[0])
        section["NumberOfLinenumbers"] = hex(struct.unpack("<H", file.read(2))[0])
        section["Characteristics"] = get_flags(struct.unpack("<I", file.read(4))[0], c.IMAGE_SECTION_CHARACTERISTICS)
        section_list.append(section)

    return section_list

def analyze(header, file=None) -> dict:
    info = dict()
    info["PE Header"] = parse_pe_header(header, file)
    info["Sections"] = list_sections(info["PE Header"], file)
    return info