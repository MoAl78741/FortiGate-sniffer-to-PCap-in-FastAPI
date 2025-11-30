import re
import collections
import binascii
import datetime
import time
import os
from typing import Tuple, Deque, Optional, BinaryIO

class DataSource_File:
    """
    Handles reading from a source file.

    This class provides a wrapper around file reading operations, keeping track
    of the file size and providing methods to read lines.
    """
    def __init__(self, filename: str):
        """
        Initialize the DataSource_File.

        Args:
            filename: The path to the file to read.
        """
        self.sourcefile: BinaryIO = open(filename, "r")
        self.sourcefile_size: int = 0

        # save the size of the file
        try:
            self.sourcefile.seek(0, os.SEEK_END)
            self.sourcefile_size = self.sourcefile.tell()
            self.sourcefile.seek(0, os.SEEK_SET)
        except IOError:
            # can happen when reading from stdin or fifo, etc.
            self.sourcefile_size = 0
            pass

    def getSize(self) -> int:
        """
        Returns the size of the source file.

        Returns:
            The size of the file in bytes.
        """
        return self.sourcefile_size

    def readline(self) -> str:
        """
        Reads a line from the source file.

        Returns:
            The next line from the file.
        """
        return self.sourcefile.readline()

    def close(self) -> None:
        """
        Closes the source file.
        """
        if self.sourcefile:
            self.sourcefile.close()


class PacketParser:
    """
    Parses packets from a data source.

    This class reads lines from a data source, identifies packet data,
    and parses it into binary format. It handles different output formats
    and normalizes lines if necessary.
    """
    def __init__(self, datasource: DataSource_File, compatible: bool = True, normalize_lines: bool = True):
        """
        Initialize the PacketParser.

        Args:
            datasource: The data source to read from.
            compatible: Whether to use compatibility mode for older formats.
            normalize_lines: Whether to normalize packet lines (remove long trailing segments).
        """
        self.normalize_lines = normalize_lines
        
        # compile regular expressions
        if compatible:
            # with FAC with "tcpdump -XXe -tt -s0 -ni port1 port not 22"
            self.packetLine = re.compile(r"(^[0-9a-f]*\t)|(^0x[0-9a-f]*[ \t:])")
            self.packetLineParser = re.compile(r"^(0x)?([0-9a-f]*)[\t :]*([0-9a-f ]*)[ \t][ \t]*")
        else:
            self.packetLine = re.compile(r"^0x[0-9a-f]{4}[ \t]")
            self.packetLineParser = re.compile(r"^(0x)([0-9a-f]{4})[ \t]*([0-9a-f ]*)[ \t][ \t]*")

        # 20220823: recognize 6k7k prefix
        self.headerLineTimeAbsolute = re.compile(r"^(?:\[(.*)\s*\]\s+)?([0-9]{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.([0-9]*) ")
        self.headerLineTimeRelative = re.compile(r"^(?:\[(.*)\s*\]\s+)?([0-9]*)\.([0-9]*)[ \t]")
        self.headerLineIface = re.compile(r"^([^ ]*) ([^ ]*) ")

        self.ds = datasource
        self.sourcefile_size = self.ds.getSize()

        self.wholefile: Deque[str] = collections.deque(maxlen=500)

        self.debug_linesRead = 0
        self.debug_bytesRead = 0

    def getNextLine(self) -> str:
        """
        Reads the next non-empty line from the data source.

        Returns:
            The next non-empty line stripped of whitespace.

        Raises:
            Exception: If end of file is reached.
        """
        while True:
            line = self.ds.readline()
            if len(line) == 0:
                raise Exception("end of file")
            self.debug_linesRead += 1
            self.debug_bytesRead += len(line)
            line = line.strip()
            if len(line) == 0:
                continue  # ignore empty lines

            self.wholefile.append(line)
            break
    
        return line

    def getLine(self, history: int = 0) -> str:
        """
        Gets a line from the history.
        
        Args:
            history: How far back in history to look (0 is the most recent).

        Returns:
            The line from history, or empty string if not found.
        """
        i = len(self.wholefile) - 1 - history
        while True:
            if i < 0:
                return "" # Should probably handle this better, but maintaining logic for now
            line = self.wholefile[i]
            if len(line) != 0:
                break
            i -= 1
        return line

    def normalizePacketLine(self, line: str) -> str:
        """
        Normalizes a packet line if it has a long trailing segment.

        This is used to handle cases where the packet dump has extra characters
        at the end of the line that are not part of the hex data.

        Args:
            line: The line to normalize.

        Returns:
            The normalized line.
        """
        newline = line
        x = line.split()
        if not x: return line
        last = x[-1]
        if len(last) > 16:
            newline = line[:-len(last)] + last[:(len(last)-16)] + " " + last[(len(last)-16):]

        return newline

    def parsePacketLine(self, line: str) -> Tuple[int, bytes]:
        """
        Parses a single line of packet data.

        Args:
            line: The line containing packet hex data.

        Returns:
            A tuple containing:
                - linePosition (int): The offset of the data in the packet.
                - binBytes (bytes): The parsed binary data.

        Raises:
            Exception: If the line cannot be parsed.
        """
        if self.normalize_lines:
            line = self.normalizePacketLine(line)
        g = self.packetLineParser.search(line)
        if not g:
            raise Exception("unparsable line: %s" % (line,))

        linePosition = int(g.group(2), 16)
        hexBytes = g.group(3).replace(" ", "")
        binBytes = binascii.unhexlify(hexBytes)

        return (linePosition, binBytes)
        
    def getPacketLine(self) -> Tuple[int, bytes, tuple]:
        """
        Finds and parses the next packet line.

        Returns:
            A tuple containing:
                - linePosition (int): The offset of the data.
                - binBytes (bytes): The parsed binary data.
                - additionalInfo (tuple): Additional info (timestamp, interface, direction) if this is the first line.
        """
        while True:
            line = self.getNextLine()
            #print line, (self.packetLine.search(line))
            if not (self.packetLine.search(line)):
                continue

            (linePosition, binBytes) = self.parsePacketLine(line)
            if len(binBytes) == 0:
                continue

            break

        if linePosition == 0: 
            additional = self.parseHeaderLine(self.getLine(history=1)) + (self.debug_linesRead,)
        else:
            additional = ()

        return (linePosition, binBytes, additional)

    def parseHeaderLine(self, line: str) -> Tuple[int, int, str, str]:
        """
        Parses the header line containing timestamp and interface info.

        Args:
            line: The header line to parse.

        Returns:
            A tuple containing:
                - ts (int): Timestamp (seconds).
                - us (int): Microseconds.
                - iface (str): Interface name.
                - direction (str): Traffic direction (in/out).
        """
        ts = 0
        us = 0
        slot = None # for chassis 6k7k
        iface = "unknown"
        direction = "unknown"

        # first parse data&time
        while True:
            g = self.headerLineTimeAbsolute.search(line)
            if g:
                slot = g.group(1)
                year = int(g.group(2))
                month = int(g.group(3))
                day = int(g.group(4))
                hour = int(g.group(5))
                minute = int(g.group(6))
                second = int(g.group(7))
                msec = int(g.group(8))

                line = line[len(g.group(0)):]
    
                dt = datetime.datetime(year, month, day, hour, minute, second, msec)
                #ts = int(dt.strftime("%s"))
                # the above expression does not work on Windows :(
                ts = int(time.mktime(dt.timetuple()))        
                us = int(dt.strftime("%f")) # is this right? or us = float(dt.strftime("0.%f")) ?
                break # to prevent the next check

            g = self.headerLineTimeRelative.search(line)
            if g:
                line = line[len(g.group(0)):]

                slot = g.group(1)
                ts = int(g.group(2))
                us = int(g.group(3))
                break

            # if we've exhausted all options...
            print("WARNING: cannot recognize time format")
            break

        # then find the interface and direction
        while True:
            g = self.headerLineIface.search(line)
            if g:
                iface = g.group(1)
                direction = g.group(2)
                line = line[len(g.group(0)):]
                break # to prevent the next (possible) check 

            # if we've exhausted all options...
            print("WARNING: cannot recognize interface and/or direction format")
            break

        # if this is 6k7k blade, prefix interface with blade name
        if slot is not None:
            iface = slot + "/" + iface

        #print (ts, us, iface, direction)
        return (ts, us, iface, direction)
