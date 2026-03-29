# detectors/filetype.py: module to identify either elf or pe files
import struct
from common import constants as c

def file_type(file=None):

    """
    Reads a binary file from the filepath and returns the type of binary (ELF, PE, etc.)

    Args:
        file(file): File object. Must be provided

    Returns:
        filetype(str): a string containing the type of the file. May be "None" if the file isn't recognized.
        header(any): first 64 bytes of the binary

    Raises:
        ValueError: if the file isn't provided

    """

    filetype = "None"
    header = None

    if file is None:
        raise ValueError("error: file object must be provided")

    header = file.read(64) # first 64 bytes of the file
    if(header[:4] == c.ELF_MAG0_3): # if the first 4 bytes are ELF's magic number
        filetype = "ELF"

    elif(header[:2] == b'MZ'): # if the first 2 bytes are MZ it's an MS-DOS executable. It might be a PE file
        e_lfanew = struct.unpack("<I", header[60:64])[0] # COFF offset
        file.seek(e_lfanew) # go to the offset

        # check for offset validity
        if (file.read(4) == c.PE_SIGNATURE):
            # print("COFF offset: Valid at:", e_lfanew)
            filetype = "PE"
        else:
            # print("COFF offset: INVALID at:", e_lfanew)
            filetype = "Invalid PE"

    print(f"Filetype: {filetype}")
    return header, filetype