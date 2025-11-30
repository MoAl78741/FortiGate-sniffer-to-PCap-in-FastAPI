import os
import re
import logging
from pathlib import Path
from typing import Optional, Tuple

from ..sniftran import DataSource_File, PacketParser, PacketAssembler, PcapNGWriter

logger = logging.getLogger(__name__)


class Convert2Pcap:
    def __init__(self, tid: int, cid: int, tuid: int, fname: str, file_to_convert: bytes):
        self.taskid = f'_{tid}'
        self.currentuserid = f'_{cid}'
        self.taskuserid = f'_{tuid}'
        self.file_to_convert = file_to_convert

        # Define paths
        self.base_path = Path(os.getcwd()) / 'fastapi_app' / 'utils'
        self.conv_folder = self.base_path / 'pcap_conversion_files'
        self.logs_folder = self.base_path / '_logs'

        self.filename_nopath = fname
        self.filename = self.conv_folder / fname
        self.num_of_packets_captured = ''

    def create_directories(self) -> bool:
        '''Creates and checks for directories'''
        self.logs_folder.mkdir(parents=True, exist_ok=True)
        self.conv_folder.mkdir(parents=True, exist_ok=True)
        return True

    def writeout_file(self) -> bool:
        '''Writes out file to disk for processing'''
        try:
            with open(self.filename, 'wb') as output_file:
                output_file.write(self.file_to_convert)
            return True
        except Exception as e:
            logger.error(f"Error writing file: {e}")
            raise

    def packets_captured(self) -> bool:
        '''Returns number of packets originally received by filter'''
        regex_string = r"\d+ packets received by filter"
        regex_compiled = re.compile(regex_string)

        try:
            with open(self.filename, 'r', encoding='utf-8', errors='ignore') as ofile:
                ofile_contents = ofile.read()

            regex_results = re.findall(regex_compiled, ofile_contents)
            if regex_results:
                num_packets_captured = regex_results[0].split().pop(0)
                if num_packets_captured:
                    logger.info(f"Packets originally captured in {self.filename} is {num_packets_captured}")
                    self.num_of_packets_captured = num_packets_captured
            return True
        except Exception as e:
            logger.error(f"Error reading packets captured: {e}")
            return False

    def remove_file(self, file_path: Path):
        '''Removes files from disk'''
        try:
            if file_path.exists():
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Error removing file {file_path}: {e}")

    def run_sniftran_conversion(self, input_file: Path, output_file: Path) -> int:
        '''Converts sniffer output to pcapng using sniftran'''
        try:
            # Initialize sniftran components
            ds = DataSource_File(str(input_file))
            pp = PacketParser(datasource=ds, compatible=True, normalize_lines=True)
            pc = PacketAssembler(packetparser=pp, stop_on_error=False)
            pcap = PcapNGWriter(outfile=str(output_file), debug=0)

            ifaces_blocks = {}
            ifaces_block = b""
            ifaces = set()
            packets_count = 0

            # Assemble all packets
            while True:
                eof = not pc.assemblePacket()
                if eof:
                    break

            # Process assembled packets
            binary_packets = []
            current_ifaces = set()

            while True:
                try:
                    (packetBytes, additionalInfo) = pc.getPacket()
                except IndexError:
                    break

                try:
                    iface = additionalInfo[2]
                    current_ifaces.add(iface)
                    timestamp = additionalInfo[0] * 1000000 + additionalInfo[1]
                    comment = f"({additionalInfo[3]}){' ' * (4 - len(additionalInfo[3]))}{additionalInfo[2]}"
                    binary_packets.append((iface, timestamp, comment, packetBytes))
                    packets_count += 1
                except IndexError:
                    logger.warning(f"Invalid data for packet {packets_count + 1}, ignoring")
                    continue

            # Create interface blocks for new interfaces
            for new_iface in (current_ifaces - ifaces):
                new_index = len(ifaces_blocks)
                iface_type = pcap.LINKTYPE_ETHERNET
                ifaces_blocks[new_iface] = {
                    'index': new_index,
                    'block': pcap.blockInterfaceDescription(new_iface, iface_type)
                }

            # Rebuild interface block
            if len(current_ifaces - ifaces) > 0:
                for iface in sorted(ifaces_blocks, key=lambda x: ifaces_blocks[x]['index']):
                    ifaces_block += ifaces_blocks[iface]['block']

            ifaces |= current_ifaces

            # Format packets
            blockPackets = []
            for (iface_name, timestamp, comment, packetBytes) in binary_packets:
                blockPackets.append(
                    pcap.blockEnhancedPacket(
                        packetBytes,
                        timestamp=timestamp,
                        ifaceIndex=ifaces_blocks[iface_name]['index'],
                        comment=comment
                    )
                )

            # Write to file
            if blockPackets:
                pcap.writePackets(ifaces_block, blockPackets)

            pcap.close()
            logger.info(f'Converted {packets_count} packets to {output_file}')
            return packets_count

        except Exception as e:
            logger.error(f"sniftran conversion failed: {e}")
            raise Exception(f"Conversion failed: {e}")

    def convert_to_pcap(self) -> Tuple[Optional[Path], str]:
        '''Converts sniffer output to pcap using sniftran'''
        self.create_directories()
        self.writeout_file()
        self.packets_captured()

        input_filename = self.filename
        pcap_file = self.conv_folder / f'task{self.taskid}_user{self.currentuserid}_{self.filename_nopath}.pcapng'

        try:
            packets_converted = self.run_sniftran_conversion(input_filename, pcap_file)

            if not pcap_file.exists():
                raise Exception('Unable to create PCAP File')

            # Use converted count if original count not available
            if not self.num_of_packets_captured:
                self.num_of_packets_captured = str(packets_converted)

            return pcap_file, self.num_of_packets_captured

        finally:
            # Cleanup input file
            self.remove_file(input_filename)

    @classmethod
    def run_conversion(cls, tid, cid, tuid, fname, file_to_convert) -> Tuple[Optional[Path], str]:
        '''Used to execute the class'''
        converter = cls(tid, cid, tuid, fname, file_to_convert)
        return converter.convert_to_pcap()
