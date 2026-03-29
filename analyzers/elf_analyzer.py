# analyzers/elf_analyzer.py: module that analyzes ELF binaries

def parse_elf_header(header, file=None):
    """
    Parses the ELF header and extracts all of the relevant information, like architecture.

    Args:
        header: String in binary bytes
        file: filetype object to read from

    Returns:
        header_info: a dictionary containing all of the relevant information from the header

    Raises:
        ValueError: if file is not provided
    """

    if file is None:
        raise ValueError("error: file object must be provided")

    header_info = {"Architecture": ""}

    # ----------------ELFN_Ehdr----------------------
    # check for the class of the binary
    ei_class = header[4]

    if (ei_class == 1):
        # print("Architecture: 32-bit")
        header_info["Architecture"] = "32-bit"
    elif(ei_class == 2):
        # print("Architecture: 64-bit")
        header_info["Architecture"] = "64-bit"
    else:
        print("Error: invalid class. Must be 1 or 2. Returned value:", ei_class)

    return header_info


def list_sections(file=__file__):
    raise NotImplementedError

def extract_strings(file=__file__):
    raise NotImplementedError

def analyze(header, file=None):
    if file is None:
        raise ValueError("error: file object must be provided")
    else:
        info = parse_elf_header(header, file)
        # info = info | list_sections(file)
        # info = info | extract_strings(file)
        return info