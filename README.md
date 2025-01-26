# DFIR tools repository
This repository contains a collection of digital forensics and incident response scripts and tools developed for various purposes.

## Contents
Here's a list of the tools currently available in this repository:
 - ``wiper.py``: secure file deletion tool that overwrites data using three distinct patterns (b'\x00', b'\xff', and random bytes) in user-specified number of passes, with one pattern applied per pass in a cyclical manner (used in [Behavioral analysis of user file operations with SRUM](https://www.ilyakobzar.com/p/behavioral-analysis-of-user-file) blog post).
 - ``mbr_parser.py``: read and extract MBR, parse partition tables, calculate SHA256 hashes of both the full MBR and bootstrap code, perform entropy analysis, disassemble x86 16-bit bootstrap code with pattern recognition and commenting, and generate text report (used in [Diving into Master Boot Record](https://www.ilyakobzar.com/p/diving-into-master-boot-record) blog post).

## Usage
Each tool in this repository is independent and may have its own usage instructions. Please refer to the individual tool's comments within the script for specific usage details.
