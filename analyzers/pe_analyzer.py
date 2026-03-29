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

def pe_fh_flags(characteristics=int) -> dict:
    """
    Indicates information about the Characteristics of the PE binary
    
    Args:
        characteristics(int): Taken from the Characteristics field of the PE File Header. Contains flags to be extracted in hex 

    Returns:
        flags(dict): A dictionary that contains attributes of the object or image file. Follows the format: {flag_description: flag_hex_value, ...}
    """

    flags = dict()

    aux_c = characteristics
    i = 0

    for key, value in c.IMAGE_FILE_CHARACTERISTICS.items():
        if ((aux_c % 16) * (16 ** i)) == value: # if the current digit is a valid flag
            flags[key] = hex(value)
            
            # move to the next most significant digit
            aux_c = aux_c // 16 
            i += 1
        if (aux_c == 0): break

    return flags
    

def parse_dos_header(file=None):
    """DOS Header Parser"""
    if file is None:
        raise ValueError("error: file object must be provided")

def parse_pe_header(header, file=None):
    """PE Header Parser"""
    if file is None:
        raise ValueError("error: file object must be provided")
    else:
        pe_header_info = dict()
        e_lfanew = struct.unpack("<I", header[60:64])[0] # COFF offset
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
        file_header["Characteristics (description : flag hex value)"] = pe_fh_flags(header_info[6])

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

def list_sections(file=None):
    """Lists the sections"""
    if file is None:
        raise ValueError("error: file object must be provided")

def analyze(header, file=None):
    info = parse_pe_header(header, file)
    return info