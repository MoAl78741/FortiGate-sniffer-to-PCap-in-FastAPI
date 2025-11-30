import sys
import getopt
import time
import datetime
import binascii
from typing import Set, Optional

from .parser import DataSource_File, PacketParser
from .assembler import PacketAssembler
from .writer import PcapNGWriter
from .ipsec import IPSec

class SnifTranCLI:
    """
    Command Line Interface for SnifTran.

    This class handles argument parsing, configuration, and the main execution flow
    of the packet conversion process.
    """
    def __init__(self) -> None:
        """
        Initialize the SnifTranCLI with default configuration.
        """
        self.input_file: Optional[str] = None
        self.output_file: Optional[str] = None
        self.overwrite: bool = True
        self.compat_mode: bool = True
        self.skip_packets: int = 0
        self.limit_packets: Optional[int] = None
        self.check_packet_size: bool = True
        self.interfaces_include: Set[str] = set()
        self.interfaces_exclude: Set[str] = set()
        self.interfaces_ptp: Set[str] = set()
        self.interfaces_nolink: Set[str] = set()

        self.section_size: Optional[int] = None
        self.max_packets_in_file: Optional[int] = None

        self.debug: int = 0
        self.show_packets: bool = False
        self.show_timestamps: bool = False
        self.normalize_lines: bool = True
        self.wireshark_ipsec: bool = True
        self.stop_on_error: bool = False
        self.include_packet_line: bool = False
        self.show_progress: bool = False

    def usage(self) -> None:
        """
        Print usage information to stderr.
        """
        message = "\n"
        message += "===\n"
        message += "=== SnifTran - written by Ondrej Holecek <ondrej@holecek.eu>\n"
        message += "===\n"
        message += "\n"
        message += "usage: %s --in <inputfile> [optional_parameters...]\n" % (sys.argv[0],)
        message += "\n"
        message += "   mandatory parameters:\n"
        message += "    --in <inputfile>                   ... text file with captured packets, \"-in\" can be used for compatability\n"
        message += "\n"
        message += "   optional parameters:\n"
        message += "    --out <outputfile>                 ... name of the output pcap file, by default <inputfile>.pcapng\n"
        message += "    --no-overwrite                     ... do not overwrite the output file if it already exists\n"
        message += "    --no-compat                        ... disable the compatability with new FE and FAC sniffers outputs\n"
        message += "    --skip <number>                    ... skip first <number> packets\n"
        message += "    --limit <number>                   ... save only <number> packets\n"
        message += "    --no-checks                        ... disable packet integrity checks\n"
        message += "    --no-normalize-lines               ... do not try to normalize packet lines before parsing them\n"
        message += "    --no-wireshark-ipsec               ... do not update Wireshark config file with found IPSec tunnels\n"
        message += "    --include <interface>              ... save only packets from/to this interface (can be used multiple times)\n"
        message += "    --exclude <interface>              ... ignore packets from/to this interface (can be used multiple times)\n"
        message += "    --p2p <interface>                  ... mark interface as point-to-point, will try to correctly remove artifical ethernet header\n"
        message += "    --nolink <interface>               ... for this interface, do not expect any link layer information (for sniffer with parameter 5)\n"
        message += "\n"
        message += "   pcapng parameters:\n"
        message += "    --section-size <number>            ... amount if packets in one SHB, default unlimited (Wireshark does not support anything else!)\n"
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12167
        message += "    --max-packets <count>              ... maximum amount of packets in one pcapng file, writes multiple files if neceesary\n"
        message += "\n"
        message += "   debug options:\n"
        message += "    --debug <level>                    ... enable debug on specified level (1 - ?)\n"
        message += "    --show-packets                     ... prints binary content of each packet and additional info (timestamp, interface, ...)\n"
        message += "    --show-timestamps                  ... for performance test, show timestamp before each main operation block\n"
        message += "    --stop-on-error                    ... raise an exception when packet parsing error occurres\n"
        message += "    --include-packet-line              ... inserts the first line in the original file where the packet was found\n"
        message += "    --progress                         ... show progress when parsing and assembling packets, be aware of small speed penalty\n"
        message += "\n"
        message += "notes:\n"
        message += "   FortiGate           - \"diagnose sniffer packet ...\" must be run with level 6\n"
        message += "                       - if there are issues with considering also non-packet lines, disable FE & FAC compatibility mode\n"
        message += "   FortiMail           - with compatibility mode (default) even the new format is recognized\n"
        message += "   FortiAuthenticator  - command to collect packets must be \"tcpdump -XXe -s0 -tt -ni <interface> <filter>...\"\n"
        message += "\n"
        sys.stderr.write(message)

    def readOptions(self) -> None:
        """
        Parse command line arguments and update configuration.

        Raises:
            SystemExit: If arguments are invalid or help is requested.
        """
        # be backwards compatible with the old "fgt2eth.pl"
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == "-in": sys.argv[i] = "--in"

        paramsStartFrom = 1
        # the first paramenter can be just plaintext file name without any -/-- before
        if len(sys.argv) > 1 and len(sys.argv[paramsStartFrom]) > 0 and sys.argv[paramsStartFrom][0] != "-":
            self.input_file = sys.argv[paramsStartFrom]
            paramsStartFrom += 1

        # first get options from user
        try:
            opts, args = getopt.getopt(sys.argv[paramsStartFrom:], "h", 
                         ["help", "in=", "out=", "no-overwrite", "no-compat", "skip=", "limit=", "no-checks", "include=", "exclude=", "p2p=", "nolink=", "no-normalize-lines",
                              "section-size=", "max-packets=",
                              "no-wireshark-ipsec",
                              "debug=", "show-packets", "show-timestamps", "stop-on-error", "include-packet-line", "progress"])
        except getopt.GetoptError as err:
            print(str(err)) # will print something like "option -a not recognized"
            self.usage()
            sys.exit(1)

        for o, a in opts:
            if o in ("-h", "--help"):
                self.usage()
                sys.exit(1)
            elif o in ("--in",):
                self.input_file = a
            elif o in ("--out",):
                self.output_file = a
            elif o in ("--no-overwrite",):
                self.overwrite = False
            elif o in ("--no-compat",):
                self.compat_mode = False
            elif o in ("--skip",):
                self.skip_packets = int(a)
            elif o in ("--limit",):
                self.limit_packets = int(a)
            elif o in ("--no-checks",):
                self.check_packet_size = False
            elif o in ("--include",):
                self.interfaces_include.add(a)
            elif o in ("--exclude",):
                self.interfaces_exclude.add(a)
            elif o in ("--p2p",):
                self.interfaces_ptp.add(a)
            elif o in ("--nolink",):
                self.interfaces_nolink.add(a)
            elif o in ("--section-size",):
                self.section_size = int(a)
            elif o in ("--max-packets",):
                self.max_packets_in_file = int(a)
            elif o in ("--debug",):
                self.debug = int(a)
            elif o in ("--show-packets",):
                self.show_packets = True
            elif o in ("--show-timestamps",):
                self.show_timestamps = True
            elif o in ("--no-normalize-lines",):
                self.normalize_lines = False
            elif o in ("--no-wireshark-ipsec",):
                self.wireshark_ipsec = False
            elif o in ("--stop-on-error",):
                self.stop_on_error = True
            elif o in ("--include-packet-line",):
                self.include_packet_line = True
            elif o in ("--progress",):
                self.show_progress = True
            else:
                assert False, "unhandled option"

        # configure some additional defaults
        if not self.output_file and self.input_file:
            self.output_file = "%s.pcapng" % (self.input_file,)
        
        # make sure all required parameters are present and correct
        if not self.input_file: 
            sys.stderr.write("ERROR: mandatory \"--in\" parameter is missing\n")
            self.usage()
            sys.exit(2)

        # check the existence of the output file
        exists = True
        try:
            open(self.output_file, "r")
        except IOError:
            exists = False

        if exists and not self.overwrite:
            sys.stderr.write("ERROR: output file \"%s\" already exists, and --no-overwrite parameter was used\n" % (self.output_file,))
            sys.exit(3)
        
        # if debug is enabled, show all parameters that we use
        if self.debug >= 1:
            print("DEBUG: SnifTran version: $Id: sniftran.py 33 2016-05-04 09:03:15Z oholecek $")
            print("DEBUG: parameters in use:")
            print("DEBUG:   input file: %s" % (self.input_file,))
            print("DEBUG:   output file: %s" % (self.output_file,))
            print("DEBUG:   allow output file overwrite: %s" % (self.overwrite,))
            print("DEBUG:   FE and FAD compatibility mode: %s" % (self.compat_mode,))
            print("DEBUG:   skip packets: %i" % (self.skip_packets,))
            if self.limit_packets: print("DEBUG:   limit packets: %i" % (self.limit_packets,))
            else: print("DEBUG:   limit packets: unlimited")
            print("DEBUG:   integrity checks: \"packet size\"=%s" % (self.check_packet_size,))
            print("DEBUG:   normalize lines: %s" % (self.normalize_lines,))
            print("DEBUG:   include interfaces: \"%s\"" % ("\", \"".join(self.interfaces_include),))
            print("DEBUG:   exclude interfaces: \"%s\"" % ("\", \"".join(self.interfaces_exclude),))
            print("DEBUG:   p2p interfaces: \"%s\"" % ("\", \"".join(self.interfaces_ptp),))
            print("DEBUG:   nolink interfaces: \"%s\"" % ("\", \"".join(self.interfaces_nolink),))
            if self.section_size: print("DEBUG:   section size: %i" % (self.section_size,))
            else: print("DEBUG:   section size: unlimited")
            if self.max_packets_in_file: print("DEBUG:   max packets in file: %i" % (self.max_packets_in_file,))
            else: print("DEBUG:   max packets in file: unlimited")
            print("DEBUG:   debug level: %i" % (self.debug,))
            print("DEBUG:   show packets: %s" % (self.show_packets,))
            print("DEBUG:   show timestamps: %s" % (self.show_timestamps,))
            print("DEBUG:   process ipsec for wireshark: %s" % (self.wireshark_ipsec,))
            print("DEBUG:   stop on error: %s" % (self.stop_on_error,))
            print("DEBUG:   include packet line: %s" % (self.include_packet_line,))
            print("DEBUG:   show progress: %s" % (self.show_progress,))

    def process(self) -> None:
        """
        Execute the main packet conversion process.

        This method:
        1. Initializes the data source, parser, assembler, and writer.
        2. Reads packets from the input file.
        3. Assembles them into full packets.
        4. Writes them to the output PCAPng file.
        5. Optionally handles IPSec tunnel discovery and Wireshark configuration.
        """
        #timestamp_start = int (datetime.datetime.now().strftime("%s"))
        # the above expression does not work on Windows :(
        timestamp_start = int(time.mktime(datetime.datetime.now().timetuple()))
        if self.show_timestamps:
            print("DEBUG: processing started at %i, referred as T" % (timestamp_start,))

        ds = DataSource_File(self.input_file)

        pp = PacketParser(datasource = ds, compatible=self.compat_mode, normalize_lines=self.normalize_lines)
        pc = PacketAssembler(packetparser = pp, stop_on_error=self.stop_on_error)
        pcap = PcapNGWriter(outfile = self.output_file, max_in_file = self.max_packets_in_file, debug=self.debug)
        
        
        ifaces_blocks = {}   # holds reusable block of interfaces - key is the index in pcap
        ifaces_block = b""
        ifaces = set() # holds all known interfaces
        
        packets_assembled = 0
        packets_read = 0
        packets_formated = 0
        
        while True:
            eof = False
        
            # first assemble preconfigured amount of packets
            if self.debug >= 2:
                print("DEBUG: assembling packets from input file")
            if self.show_timestamps: 
                timestart_start_assembling = int(time.mktime(datetime.datetime.now().timetuple()))
                print("DEBUG: assembling started at %i, T+%i" % (timestart_start_assembling, timestart_start_assembling-timestamp_start))

            packets_assembled_in_section = 0
            while True:
                if self.section_size and (packets_assembled_in_section >= self.section_size):
                    break
        
                eof = not pc.assemblePacket()
                packets_assembled += 1
                packets_assembled_in_section += 1
                if (self.debug >= 3) and (packets_assembled % 10000 == 0):
                    print("DEBUG: assembled %i packets" % (packets_assembled,))

                # display progress if requested
                if self.show_progress and packets_assembled % 1000 == 0: 
                    progress_current = pp.debug_bytesRead * 100 / pp.sourcefile_size
                    if 'progress_last' not in vars():
                        progress_last = None
                    if progress_current != progress_last:
                        sys.stdout.write("PROGRESS: assembling: %3i %%\r" % (pp.debug_bytesRead * 100 / pp.sourcefile_size))
                        sys.stdout.flush()
                        progress_last = progress_current
        
                if eof:
                    break
            if self.debug >= 2:
                print("DEBUG: assembled %i packets totally, %i in current section" % (packets_assembled, packets_assembled_in_section,))
            
            # then go through all of them, and
            # - extract the interface name (to see whenther we need to define a new iface in pcap)
            # - move packet to the local list called "packets"
            current_ifaces = set()  # holds a set of interfaces used in this part of the capture
            binary_packets = []
        
            if self.debug >= 2:
                print("DEBUG: reading packets")
            if self.show_timestamps: 
                timestart_start_reading = int(time.mktime(datetime.datetime.now().timetuple()))
                print("DEBUG: reading started at %i, T+%i" % (timestart_start_reading, timestart_start_reading-timestamp_start))

            packets_read_in_section = 0
            while True:
                try:
                    (packetBytes, additionalInfo) = pc.getPacket()
                except IndexError:
                    break

                try:
                    iface = additionalInfo[2]
                    if (len(self.interfaces_include) > 0) and (iface not in self.interfaces_include):
                        continue
                    if (len(self.interfaces_exclude) > 0) and (iface in self.interfaces_exclude):
                        continue
                    current_ifaces.add(iface)
                    timestamp = additionalInfo[0] * 1000000 + additionalInfo[1]  # convert seconds and useconds to one large us number
                    comment = "(%s)%s%s" % (additionalInfo[3], " "*(4-len(additionalInfo[3])), additionalInfo[2],) # comment contains the direction of the packet and the interface
                    if self.include_packet_line:
                        comment += "  %5i" % (additionalInfo[4],)
                    binary_packets.append( (iface, timestamp, comment, packetBytes,) )
                    packets_read += 1
                    packets_read_in_section += 1
                    if (self.debug >= 3) and (packets_read % 10000 == 0):
                        print("DEBUG: prepared %i packets" % (packets_read,))
                except IndexError:
                    print("WARNING: invalid data for packet %i, ignoring" % (packets_read+1,))
                    continue

            if self.debug >= 2:
                print("DEBUG: read packets %i totally, %i in current section" % (packets_read, packets_read_in_section,))
        
            if self.debug >= 2:
                print("DEBUG: looking for yet unknown interfaces")
            if self.show_timestamps: 
                timestart_start_interfaces = int(time.mktime(datetime.datetime.now().timetuple()))
                print("DEBUG: interfaces lookup started at %i, T+%i" % (timestart_start_interfaces, timestart_start_interfaces-timestamp_start))

            # for new interfaces, create a pcap interface block
            for new_iface in (current_ifaces-ifaces):
                new_index = len(ifaces_blocks)
                iface_type = pcap.LINKTYPE_ETHERNET

                # if this interface is marked as point-to-point, make it also in pcap interface description
                if new_iface in self.interfaces_ptp:
                    iface_type = pcap.LINKTYPE_NULL

                # if this interface is marked as nolink, do not modify the packet, but mark as RAW (layer 3)
                if new_iface in self.interfaces_nolink:
                    iface_type = pcap.LINKTYPE_RAW

                ifaces_blocks[new_iface] = { 'index' : new_index, 'block' : pcap.blockInterfaceDescription(new_iface, iface_type) }
                if self.debug >= 3:
                    print("DEBUG: new iface found: \"%s\", assigning index %i" % (new_iface, ifaces_blocks[new_iface]['index'],))
            if self.debug >= 2:
                print("DEBUG: found %i new interfaces" % (len(current_ifaces-ifaces),))
        
            # if the amount of interfaces has changed, rebuild the block
            if len(current_ifaces - ifaces) > 0:
                if self.debug >= 2:
                    print("DEBUG: rebuilding interfaces block")
                for iface in sorted(ifaces_blocks, key=lambda x: ifaces_blocks[x]['index']):
                    #print "new interface: ", iface, ifaces_blocks[iface]
                    ifaces_block += ifaces_blocks[iface]['block']
        
            ifaces |= current_ifaces   # copy new interfaces to known ifaces
        
            # prepare the packets block
            if self.debug >= 2:
                print("DEBUG: formating packets")
            if self.show_timestamps: 
                timestart_start_formating = int(time.mktime(datetime.datetime.now().timetuple()))
                print("DEBUG: packet formating started at %i, T+%i" % (timestart_start_formating, timestart_start_formating-timestamp_start))

            packets_formated_in_section = 0
            ignore_packets = 0
            blockPackets = []
            for i in range(self.skip_packets, len(binary_packets)):
                (iface_name, timestamp, comment, packetBytes) = binary_packets[i]
                if self.show_packets:
                    print("DEBUG: packet: iface=\"%s\", timestamp=\"%s\", comment=\"%s\", binary: \"%s\"" % (
                                           iface_name, timestamp, comment, binascii.hexlify(packetBytes)))

                # if this interface is marked as point-to-point, remove artificial ethernet header
                if iface_name in self.interfaces_ptp:
                    packetBytes = packetBytes[10:]  # remove 6 bytes for src and 6 byte for dst MAC, keep 2 byte protocol ("ethertype") 
                    packetBytes[0] = 0              # however,  because LINKTYPE_NULL is used as L2 and it needs first 4 bytes for protocl
                    packetBytes[1] = 0              # we need to prepend another 2 bytes (0x0) to ethertype
        
                # if allowed, check whether the packet has the right size
                # - currently only IPv4 over ethernet is supported
                if self.check_packet_size:
                    ethertype = "0x%02x%02x" % (packetBytes[12], packetBytes[13],)
                    if ethertype == "0x0800": 
                        totallength = int("0x%02x%02x" % (packetBytes[16], packetBytes[17],), 16)
                        if totallength+14 > len(packetBytes):
                            print("WARNING: packet #%i is not complete, ignoring" % (packets_formated+1,))
                            if self.debug >= 3:
                                print("DEBUG: packet size from IP header %i, (%i including ethernet) total packet size %i" % (totallength, totallength+14, len(packetBytes),))
                            ignore_packets = 1
        
                if ignore_packets > 0:
                    ignore_packets -= 1
                else:
                    blockPackets.append(pcap.blockEnhancedPacket(packetBytes, timestamp=timestamp, ifaceIndex=ifaces_blocks[iface_name]['index'], comment=comment))
        
                packets_formated += 1
                packets_formated_in_section += 1
                if (self.debug >= 3) and (packets_formated % 10000 == 0):
                    print("DEBUG: formated %i packets" % (packets_formated,))

                if self.show_progress and packets_formated % 1000 == 0:
                    progress_current = i * 100 / len(binary_packets)
                    if 'progress_last' not in vars():
                        progress_last = None
                    if progress_current != progress_last:
                        sys.stdout.write("PROGRESS: formating: %3i %%\r" % (progress_current,))
                        sys.stdout.flush()
                        progress_last = progress_current

                if self.limit_packets and (packets_formated >= self.limit_packets):
                    break
            if self.debug >= 2:
                print("DEBUG: formated %i packets totally, %i in current section" % (packets_formated, packets_formated_in_section,))
        
            # now create a new section with interfaces and the packets we have collected in this block
            if self.debug >= 2:
                print("DEBUG: saving current section into the output file")
            if self.show_timestamps: 
                timestart_start_saving = int(time.mktime(datetime.datetime.now().timetuple()))
                print("DEBUG: packet saving started at %i, T+%i" % (timestart_start_saving, timestart_start_saving-timestamp_start))

            pcap.writePackets(ifaces_block, blockPackets)
        
            # if that was the last packet, we can finish here
            if eof:
                break

        # if wireshark SA check is enabled
        if self.wireshark_ipsec:
            if self.show_timestamps: 
                timestart_start_ipsec = int(time.mktime(datetime.datetime.now().timetuple()))
                print("DEBUG: ipsec SA lookup started at %i, T+%i" % (timestart_start_ipsec, timestart_start_ipsec-timestamp_start))

            ipsec = IPSec(sourcefile = self.input_file, debug=self.debug, show_progress=self.show_progress)
            ipsec.find_tunnels()
            ipsec.configure_wireshark()

        if self.show_timestamps: 
            timestart_done = int(time.mktime(datetime.datetime.now().timetuple()))
            print("DEBUG: finally done at %i, T+%i" % (timestart_done, timestart_done-timestamp_start))

def main():
    cli = SnifTranCLI()
    cli.readOptions()
    cli.process()

if __name__ == "__main__":
    main()
