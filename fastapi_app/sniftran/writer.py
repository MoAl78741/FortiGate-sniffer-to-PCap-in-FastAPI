import struct
import os
from typing import List, Optional

class PcapNGWriter:
    """
    Writes packets to a PcapNG file.

    This class handles the creation of PcapNG blocks (Section Header, Interface Description,
    Enhanced Packet) and writes them to the output file. It also supports splitting
    output into multiple files if a maximum packet count is specified.
    """
    LINKTYPE_ETHERNET = 1
    LINKTYPE_PPP = 9
    LINKTYPE_RAW = 101
    LINKTYPE_NULL = 0

    def __init__(self, outfile: str, max_in_file: Optional[int] = None, debug: int = 0):
        """
        Initialize the PcapNGWriter.

        Args:
            outfile: The path to the output file.
            max_in_file: Maximum number of packets per file (for splitting).
            debug: Debug level.
        """
        self.max_in_file = max_in_file
        self.debug = debug

        # split file name, in case we need to have more than one files
        if outfile[-7:] == '.pcapng': 
            self.output_file_base = outfile[:-7]
            self.output_file_suffix = '.pcapng'
        else:
            self.output_file_base = outfile
            self.output_file_suffix = ''

        # open the file with the original filename, it can be renamed in the future
        self.f_current = "%s%s" % (self.output_file_base, self.output_file_suffix)
        self.f = open(self.f_current, "wb")
        self.f_packet_count = 0
        self.f_file_count = 1

    def writePackets(self, blockIfaces: bytes, blockPackets: List[bytes]) -> None:
        """
        Writes a block of packets to the file.

        This method writes the Section Header Block (if needed), Interface Description Blocks,
        and then the Enhanced Packet Blocks. It handles file splitting if max_in_file is set.

        Args:
            blockIfaces: The interface block bytes (concatenated Interface Description Blocks).
            blockPackets: A list of packet bytes (Enhanced Packet Blocks).
        """
        options = self.blockOption(4, "SnifTran ($Revision: 33 $) by Ondrej Holecek")   # application name
        options += self.blockEndOfOptions()

        packet_index = 0
        while len(blockPackets[packet_index:]) > 0:  # when we still have packets to save...
            if self.max_in_file is None:
                # when amount of packets in file is unlimited, we have as many slots as we need
                slots_free = len(blockPackets[packet_index:])
                if self.debug >= 2:
                    print("DEBUG: amount of packets in file is unlimited, packets to save: %i, file already contains: %i, free slots: %i" % (
                                         len(blockPackets[packet_index:]), self.f_packet_count, slots_free,))
            else:
                # otherwise we need to be more cautious
                slots_free = self.max_in_file - self.f_packet_count
                if self.debug >= 2:
                    print("DEBUG: amount of packets in file is limited to %i, packets to save: %i, file already contains: %i, free slots current cycle: %i" % (
                                         self.max_in_file, len(blockPackets[packet_index:]), self.f_packet_count, slots_free,))

            if slots_free == 0:
                # we need to write packets, but there are not slots in the file
                # so we need to open another file
                self.f.close()

                if self.f_file_count == 1: # if this was the first, original, file, rename it to the split format
                    newname = "%s.part%03i%s" % (self.output_file_base, 1, self.output_file_suffix)
                    if self.debug >= 1:
                        print("DEBUG: renaming original output file '%s' to '%s'" % (self.f_current, newname,))
                    os.rename(self.f_current, newname)

                self.f_file_count += 1
                self.f_current = "%s.part%03i%s" % (self.output_file_base, self.f_file_count, self.output_file_suffix)
                if self.debug >= 1:
                    print("DEBUG: opening new output file '%s'" % (self.f_current,))
                self.f = open(self.f_current, "wb")

                # reset the packet count as we have a new file
                self.f_packet_count = 0
                slots_free = self.max_in_file - self.f_packet_count

            # write packets to available slots
            data = blockIfaces + bytearray().join(blockPackets[packet_index:packet_index+slots_free])

            block = struct.pack(">I", 0x0A0D0D0A)
            block += struct.pack(">I", 28+len(options))
            block += struct.pack(">I", 0x1A2B3C4D)
            block += struct.pack(">HH", 1, 0)
            block += struct.pack(">q", -1)  # section length
            block += options
            block += struct.pack(">I", 28+len(options))
            block += data

            self.f.write(block)
            self.f_packet_count += len(blockPackets[packet_index:packet_index+slots_free])
            if self.debug >= 3:
                print("DEBUG: written %i packets, %i bytes to the current output file, now the file contains: %i" % (len(blockPackets[packet_index:packet_index+slots_free]), len(block), self.f_packet_count))

            packet_index += len(blockPackets[packet_index:packet_index+slots_free])

    
    def blockInterfaceDescription(self, iface: str, linktype: int, tsresol: int = 6) -> bytes:
        """
        Creates an Interface Description Block (IDB).

        Args:
            iface: Interface name.
            linktype: Link type (e.g., LINKTYPE_ETHERNET).
            tsresol: Timestamp resolution (default 6 for microseconds).

        Returns:
            The binary representation of the IDB.
        """
        options = self.blockOption(2, iface)   # interface name
        options += self.blockOption(9, chr(tsresol) ) # timestamp resolution, default 6 means microseconds
        options += self.blockEndOfOptions()

        block = struct.pack(">I", 0x00000001)
        block += struct.pack(">I", 20+len(options))
        block += struct.pack(">H", linktype)  # linktype
        block += struct.pack(">H", 0)  # reserved
        block += struct.pack(">i", -1) # snaplen (max possible lenght of captured packet)
        block += options
        block += struct.pack(">I", 20+len(options))

        #print "interface block length:", len(block), ", reported length:", 20+len(options)
        return block
    
    def blockEnhancedPacket(self, packet: bytes, timestamp: int, ifaceIndex: int, comment: str = "") -> bytes:
        """
        Creates an Enhanced Packet Block (EPB).

        Args:
            packet: Packet data (binary).
            timestamp: Timestamp in the resolution specified in IDB.
            ifaceIndex: Interface index (0-based index of IDB).
            comment: Comment string to attach to the packet.

        Returns:
            The binary representation of the EPB.
        """
        options = self.blockOption(1, comment)
        options += self.blockEndOfOptions()

        packetPad = 0
        if (len(packet) % 4) > 0:
            packetPad = 4-(len(packet) % 4)

        block = struct.pack(">I", 0x00000006)        # block type
        block += struct.pack(">I", 32+len(packet)+packetPad+len(options))
        block += struct.pack(">I", ifaceIndex)  # interface id
        block += struct.pack(">Q", timestamp)  # timestamp 64bit (in format docs this is shown as two 32bit numbers)
        block += struct.pack(">I", len(packet))  # capture length
        block += struct.pack(">I", len(packet))  # packet length
        block += packet
        for i in range(packetPad):
            block += struct.pack(">b", 0)
        block += options
        block += struct.pack(">I", 32+len(packet)+packetPad+len(options))

        #print "packet length:", len(packet), "padding:", packetPad, "reported:", 32+len(packet)+packetPad+len(options), "real:", len(block)

        return block
    
    def blockOption(self, code: int, value: str) -> bytes:
        """
        Creates an option block.

        Args:
            code: Option code.
            value: Option value (string).

        Returns:
            The binary representation of the option block, including padding.
        """
        valuePad = 0
        if len(value) % 4 > 0:
            valuePad = 4-(len(value) % 4)

        block = struct.pack(">H", code)
        block += struct.pack(">H", len(value))
        block += str.encode(value)
        for i in range(valuePad):
            block += struct.pack(">b", 0)
        return block

    def blockEndOfOptions(self) -> bytes:
        """
        Creates an end of options block.

        Returns:
            The binary representation of the end of options block.
        """
        block = struct.pack(">H", 0)
        block += struct.pack(">H", 0)
        return block

    def close(self) -> None:
        """
        Closes the writer file.
        """
        if self.f:
            self.f.close()
