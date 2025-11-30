import collections
from typing import Deque, Tuple, Optional
from .parser import PacketParser

class PacketAssembler:
    """
    Assembles packets from parsed lines.

    This class takes a PacketParser and uses it to read packet lines.
    It assembles these lines into complete packets, handling cases where
    a packet is split across multiple lines.
    """
    def __init__(self, packetparser: PacketParser, stop_on_error: bool = False):
        """
        Initialize the PacketAssembler.

        Args:
            packetparser: The PacketParser instance to use for reading lines.
            stop_on_error: Whether to raise an exception when a parsing error occurs.
        """
        self.pp = packetparser
        self.stop_on_error = stop_on_error
        self.packetLines: Deque[Tuple[int, bytes, tuple]] = collections.deque()
        self.packets: Deque[Tuple[bytearray, tuple]] = collections.deque()

    def assemblePacket(self) -> bool:
        """
        Reads as many lines as necessary to assemble a full packet.

        This method reads lines from the parser until it encounters a new packet
        start or EOF. It then assembles the lines of the *previous* packet
        into a single bytearray.

        Returns:
            True if a packet was successfully assembled (or if there are more packets),
            False if EOF was reached and no more packets can be assembled.
        """
        EOF = False

        while True:
            try:
                (offset, content, additional) = self.pp.getPacketLine()
            except Exception as e:
                if str(e) == "end of file":
                    EOF = True
                else: 
                    print("WARNING: packet decoder problem occurred on line %i, packet ignored" % (self.pp.debug_linesRead))
                    if self.stop_on_error:
                        raise
                    continue

            if EOF or (offset == 0):  # extract the old packet
                if len(self.packetLines) > 0: 
                    packetLength = self.packetLines[-1][0] + len(self.packetLines[-1][1])
                    binaryPacket = bytearray(packetLength)
                    additionalInfo = ()
    
                    while len(self.packetLines) > 0:
                        (c_offset, c_content, c_additional) = self.packetLines.popleft()
                        if c_offset == 0:
                            additionalInfo = c_additional # additional information is only in the first line of the packet
                        binaryPacket[c_offset:c_offset+len(c_content)] = c_content
    
                    self.packets.append( (binaryPacket, additionalInfo) )
                    if not EOF:
                        self.packetLines.append( (offset, content, additional) )
                    break

            if not EOF:
                self.packetLines.append( (offset, content, additional) )
            if EOF:
                break
        
        if EOF:
            return False
        else:
            return True


    def getPacketsCount(self) -> int:
        """
        Returns the number of assembled packets currently in the queue.

        Returns:
            The number of packets.
        """
        return len(self.packets)
            
    def getPacket(self) -> Tuple[bytearray, tuple]:
        """
        Returns the next assembled packet from the queue.

        Returns:
            A tuple containing:
                - binaryPacket (bytearray): The assembled packet data.
                - additionalInfo (tuple): Additional info (timestamp, interface, etc.).
        
        Raises:
            IndexError: If the queue is empty.
        """
        return self.packets.popleft()
