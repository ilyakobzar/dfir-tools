'''
POC code for MBR analysis designed to:
- Export MBR to mbr.bin file
- Extract MBR metadata including partition tables
- Calculate SHA256 hashes for MBR and bootstrap code
- Disassemble x86 16-bit bootstrap code
'''

import sys
import struct
import hashlib
import math
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
from tabulate import tabulate
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

@dataclass
class PartitionEntry:
    boot_indicator: int
    starting_chs: Tuple[int, int, int]
    partition_type: int
    ending_chs: Tuple[int, int, int]
    starting_lba: int
    size_in_sectors: int

class MBRParser:
    def __init__(self, filename: str):
        self.filename = filename
        self.bootstrap_code = None
        self.partition_entries = []
        self.boot_signature = None
        self.mbr_data = None
        self.mbr_hash = None
        self.entropy = None
        self.partition_types = {
            0x00: "Empty", 0x01: "FAT12,CHS", 0x04: "FAT16 (16-32MB), CHS", 0x05: "Microsoft Extended, CHS",
            0x06: "FAT16 (32MB-2GB), CHS", 0x07: "NTFS", 0x0B: "FAT32, CHS", 0x0C: "FAT32, LBA",
            0x0E: "FAT16 (32MB-2GB), LBA", 0x0F: "Microsoft Extended, LBA", 0x11: "Hidden FAT12, CHS", 
            0x14: "Hidden FAT16 (16-32MB), CHS", 0x16: "Hidden FAT16 (32MB-2GB), CHS",
            0x17: "Hidden NTFS", 0x1B: "Hidden FAT32, CHS", 0x1C: "Hidden FAT32, LBA",
            0x1E: "Hidden FAT16 (32MB-2GB), LBA", 0x27: "Windows Recovery Environment", 
            0x42: "Microsoft Dynamic Disk", 0x82: "Linux Swap", 0x83: "Linux", 
            0x84: "Hibernation", 0x85: "Linux extended", 0x86: "NTFS Volume Set", 
            0x87: "NTFS Volume Set", 0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xA6: "OpenBSD", 0xA8: "Mac OSX",
            0xA9: "NetBSD", 0xAB: "Mac OSX Boot", 0xAF: "Mac OSX HFS/HFS+", 0xB7: "BSDI", 0xB8: "BSDI swap",
            0xBE: "Solaris boot", 0xBF: "Solaris", 0xEB: "BeOS, Haiku", 0xEE: "EFI GPT Disk",
            0xEF: "EFI System Partition", 0xFB: "VMware File System", 0xFC: "VMware swap" 
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data using pure Python."""
        if not data:
            return 0.0
        
        # Count the frequency of each byte
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calculate probabilities and entropy
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            prob = count / total
            entropy -= prob * (math.log2(prob) if prob > 0 else 0)
        
        return entropy

    def read_chs(self, chs_bytes: bytes) -> Tuple[int, int, int]:
        """Convert CHS bytes to cylinder, head, sector tuple."""
        head = chs_bytes[0]
        sector = chs_bytes[1] & 0x3F  # Lower 6 bits
        cylinder = ((chs_bytes[1] & 0xC0) << 2) + chs_bytes[2]
        return (cylinder, head, sector)

    def parse_partition_entry(self, data: bytes) -> PartitionEntry:
        """Parse a 16-byte partition entry."""
        boot_indicator = data[0]
        starting_chs = self.read_chs(data[1:4])
        partition_type = data[4]  # Volume type
        ending_chs = self.read_chs(data[5:8])
        starting_lba = struct.unpack("<I", data[8:12])[0]
        size_in_sectors = struct.unpack("<I", data[12:16])[0]

        return PartitionEntry(
            boot_indicator=boot_indicator,
            starting_chs=starting_chs,
            partition_type=partition_type,
            ending_chs=ending_chs,
            starting_lba=starting_lba,
            size_in_sectors=size_in_sectors
        )

    def calculate_hash(self, data: bytes) -> str:
        """Calculate SHA256 hash of the data."""
        return hashlib.sha256(data).hexdigest()

    def parse(self):
        """Parse the MBR from the disk."""
        try:
            with open(self.filename, 'rb') as f:
                self.mbr_data = f.read(512)
                
                if len(self.mbr_data) != 512:
                    raise ValueError("Invalid MBR size - must be exactly 512 bytes")

                # Calculate SHA256 hash of entire MBR
                self.mbr_hash = self.calculate_hash(self.mbr_data)

                # Calculate entropy using pure Python math
                self.entropy = self.calculate_entropy(self.mbr_data)

                # Parse bootstrap code (0x000 - 0x1BD)
                self.bootstrap_code = self.mbr_data[0:446]

                # Parse partition entries (0x1BE - 0x1FD)
                for i in range(4):
                    offset = 446 + (i * 16)
                    partition_data = self.mbr_data[offset:offset + 16]
                    self.partition_entries.append(self.parse_partition_entry(partition_data))

                # Parse boot signature (0x1FE - 0x1FF)
                self.boot_signature = self.mbr_data[510:512]

                if self.boot_signature != b'\x55\xAA':
                    raise ValueError("Invalid boot signature - not a valid MBR")

        except FileNotFoundError:
            print(f"Error: Could not find file {self.filename}")
            sys.exit(1)
        except Exception as e:
            print(f"Error parsing MBR: {str(e)}")
            sys.exit(1)

    def get_partition_offset(self, partition_number: int) -> int:
        """Calculate the absolute offset for a partition entry."""
        return 0x1BE + (partition_number - 1) * 16

    def get_partition_type_desc(self, type_code: int) -> str:
        """Return description for partition type code."""
        return self.partition_types.get(type_code, "Unknown")

    def get_partition_table(self):
        """Generate partition table data for tabulate."""
        headers = [
            "Partition",
            "Boot flag\n(+0x00)",
            "Type\n(+0x04)",
            "Starting CHS*\n(+0x01)",
            "Ending CHS*\n(+0x05)", 
            "Starting LBA**\n(+0x08)",
            "Size (sectors)\n(+0x0C)",
            "Size (MB)"
        ]
        
        table_data = []
        for i, entry in enumerate(self.partition_entries, 1):
            table_data.append([
                f"{i} (0x{self.get_partition_offset(i):03X})",
                f"0x{entry.boot_indicator:02X}" + (" (System, Boot)" if entry.boot_indicator == 0x80 else " (Default)" if entry.boot_indicator == 0x00 else " (Invalid!!! Investigate!)"),
                f"0x{entry.partition_type:02X} ({self.get_partition_type_desc(entry.partition_type)})",
                f"({entry.starting_chs[0]}, {entry.starting_chs[1]}, {entry.starting_chs[2]})",
                f"({entry.ending_chs[0]}, {entry.ending_chs[1]}, {entry.ending_chs[2]})",
                entry.starting_lba,
                entry.size_in_sectors,
                f"{entry.size_in_sectors * 512 / 1024 / 1024:.2f}"
            ])
        
        return headers, table_data

    def export_mbr(self, output_file='mbr.bin'):
        """Export the entire MBR to a binary file."""
        try:
            with open(output_file, 'wb') as f:
                f.write(self.mbr_data)
            print(f"MBR exported to {output_file}")
        except Exception as e:
            print(f"Error exporting MBR: {str(e)}")

    def disassemble_bootstrap(self):
        """Disassemble the bootstrap code using Capstone."""
        # Create Capstone instance for 16-bit x86 mode (real mode)
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        
        '''print("\nBootstrap Code Disassembly:")
        print("=" * 30)
        
        # Disassemble bootstrap code
        for i, insn in enumerate(md.disasm(self.bootstrap_code, 0x7C00)):
            print(f"0x{insn.address:04x}:\t{insn.mnemonic}\t{insn.op_str}")'''
        
        print("\nNote: Disassembly assumes 16-bit real mode addressing used in early boot process.")

    def analyze_bootstrap_code(self) -> Dict[str, Any]:
        """Analyze bootstrap code and add comments on common parts."""
        common_patterns = {
            "xor\tax, ax": "Zero out AX register",
            "mov\tss, ax": "Set Stack Segment to 0",
            "mov\tsp, 0x7c00": "Set Stack Pointer to 0x7C00 (standard MBR load address)",
            "mov\tsi, sp": "Set Source Index to Stack Pointer",
            "mov\tes, ax": "Set Extra Segment to 0",
            "mov\tds, ax": "Set Data Segment to 0",
            "sti": "Enable interrupts",
            "cld": "Clear direction flag (forward string operations)",
            "int\t0x13": "BIOS Disk Service interrupt",
            "int\t0x10": "BIOS Video Service interrupt",
            "jmp\t0x0000:0x7c00": "Far jump to reset CS:IP to 0x0000:0x7C00",
        }
        
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        commented_code = []
        analysis_results = {
            "common_patterns_found": [],
        }
        
        for instruction in md.disasm(self.bootstrap_code, 0x7C00):
            commented_instruction = f"0x{instruction.address:04x}:\t{instruction.mnemonic}\t{instruction.op_str}"
            
            for pattern, comment in common_patterns.items():
                if pattern in commented_instruction:
                    commented_instruction += f"\t\t\t\t; {comment}"
                    analysis_results["common_patterns_found"].append(pattern)
                    break
            
            commented_code.append(commented_instruction)
        
        analysis_results["commented_code"] = commented_code
        return analysis_results

    def print_info(self):
        """Print parsed MBR information using tabulate."""
        
        # MBR Hash and basic info
        mbr_info = [
            ["File", self.filename],
            ["SHA256", self.mbr_hash],
            ["Size", "512 bytes (0x000-0x1FF)"],
            ["Entropy", f"{self.entropy:.4f}"]
        ]
        print("\nMBR Overview [0x000-0x1FF]:")
        print(tabulate(mbr_info, tablefmt="grid"))
        
        # Bootstrap code information
        bootstrap_info = [
            ["Size", f"{len(self.bootstrap_code)} bytes"],
            ["First 16 bytes (hex)", self.bootstrap_code[:16].hex()],
            ["SHA256", self.calculate_hash(self.bootstrap_code)]
        ]
        print("\nBootstrap Code Metadata [0x000-0x1BD]:")
        print(tabulate(bootstrap_info, tablefmt="grid"))


        # Partition table
        headers, table_data = self.get_partition_table()
        print("\nPartition Table [0x1BE-0x1FD]:")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

        # Partition Analysis
        active_partitions = [
            entry for entry in self.partition_entries 
            if entry.boot_indicator == 0x80
        ]
                # Addressing Mode Explanation
        print("\n*CHS (Cylinder-Head-Sector):")
        print("  - Cylinder: Represents concentric circles on the disk")
        print("  - Head: Represents the read/write head position")
        print("  - Sector: Represents the specific sector within a track")
        print("**LBA (Logical Block Addressing):")
        print("  - Starting LBA indicates the first logical sector of the partition")
        
        print("\nPartition Analysis:")
        print(f"Total Partitions: {len(self.partition_entries)}")
        print(f"Active Partitions: {len(active_partitions)}")
       
        
        # Boot Signature
        signature_info = [
            ["Boot Signature (hex)", self.boot_signature.hex()],
            ["Valid", "Yes" if self.boot_signature == b'\x55\xAA' else "No"],
            ["Byte Interpretation", "Standard MBR Signature" if self.boot_signature == b'\x55\xAA' else "Nonstandard Signature"]
        ]
        print("\nBoot Signature [0x1FE-0x1FF]:")
        print(tabulate(signature_info, tablefmt="grid"))
        
        # Bootstrap code analysis
        bootstrap_analysis = self.analyze_bootstrap_code()
        print("\nCommented Bootstrap Code:")
        for line in bootstrap_analysis["commented_code"]:
            print(line)


def export_report(parser, report_filename='mbr_report.txt'):
    """Export the MBR analysis report to a text file."""
    import contextlib
    import io

    # Capture print output to a string
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        parser.print_info()
        # Additional details like disassembly can be added here if needed
        parser.disassemble_bootstrap()

    try:
        with open(report_filename, 'w') as f:
            f.write(output.getvalue())
        print(f"Report exported to {report_filename}")
    except Exception as e:
        print(f"Error exporting report: {str(e)}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python mbr_parser.py <disk_image>")
        sys.exit(1)

    parser = MBRParser(sys.argv[1])
    parser.parse()
    
    # Always export MBR and generate report
    parser.export_mbr()
    export_report(parser)
    
    # Print info to console
    parser.print_info()
    parser.disassemble_bootstrap()

if __name__ == "__main__":
    main()