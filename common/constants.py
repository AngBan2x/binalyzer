#common/constants.py: constants used all along the project

#ELF related constants
ELF_MAG0_3 = b'\x7fELF' # the magic number (bytes 0 to 3) of the ELF Header

#PE related constants
PE_HEADER = b'MZ'
PE_SIGNATURE = b'PE\0\0'
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x14c