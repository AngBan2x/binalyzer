# binary analyzer

# import local packages
import importlib
import os, sys, struct
from detectors import file_type as ft
from common import helpers as h

def help_message(): # for proper use of running the script
    print("Usage: python bin_analyzer.py <path to binary> <arguments>")
    print("Available arguments:")
    print("-h: Help (this same page)")
    print("-a: Analyze")

def main():
    # validate command line arguments
    if (len(sys.argv) != 3 or "-h" in sys.argv or sys.argv[2] != "-a"):
        help_message()
        return

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        raise FileNotFoundError("error: file not found")
    else:
        print(f"File path: {filepath}")

    try:
        with open(filepath, "rb") as file:
            header, filetype = ft.file_type(file=file)

            module_name = f"analyzers.{filetype.lower()}_analyzer"
            analyzer = importlib.import_module(module_name)
            info = analyzer.analyze(header, file) # dictionary that shows all information of the binary
            h.rprint_dict(info, 0) # recursively print the dict in indented hierarchical order 

    except Exception as e:
        print(f"Error. Reason: {e}")

if __name__ == "__main__":
    main()