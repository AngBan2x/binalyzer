# Binalyzer
A CLI tool that serves as a binary analyzer for both ELF and PE formats

## What does it do?
Five main functionalities

| # | Functionality Description | Status |
| --- | --- | --- |
| 1. | Identification of the type of binary (ELF/PE) and validity | Done |
| 2. | Display and parse the main header (ELF header / DOS + COFF headers) | TODO |
| 3. | List sections (ELF) / segments (PE) with their attributes (name, size, offset, permissions) | TODO |
| 4. | Extract and show strings | TODO |
| 5. | Show imported and exported functions | TODO |

## Requirements to run
- Operating System: Windows or Linux
- Python installed in your system
- A binary file

## How to run
- Download the python file
- run `python binalyzer.py <path to binary> <arguments>`

### Available arguments
- `-a`: Analyze the file
- `-h`: Help

## Why?
This is a personal project, to learn about binary files and their structure depending on the Operating System

![License](https://img.shields.io/badge/license-MIT-green)