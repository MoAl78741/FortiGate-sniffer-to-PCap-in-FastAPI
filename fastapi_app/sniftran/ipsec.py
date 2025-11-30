import os
import sys
import random
from typing import Dict, Optional, Tuple

class IPSec:
    """
    Analyzes IPSec tunnels and updates Wireshark configuration.

    This class parses the input file for IPSec tunnel information (SPI, keys, algorithms)
    and updates the Wireshark `esp_sa` configuration file to enable decryption.
    """
    def __init__(self, sourcefile: str, debug: int = 0, show_progress: bool = False):
        """
        Initialize the IPSec analyzer.

        Args:
            sourcefile: The path to the source file containing packet capture and tunnel info.
            debug: Debug level.
            show_progress: Whether to show progress during analysis.
        """
        self.sourcefile = sourcefile
        self.debug = debug
        self.show_progress = show_progress
        self.tunnels: Dict[str, Dict] = {}

        self.cipher_map = { 
                            ("aes", "16") : "AES-CBC [RFC3602]",
                        }

        self.hash_map = {
                            ("sha1", "20") : "HMAC-SHA-1-96 [RFC2404]",
                        }

        if 'HOME' in os.environ:
            self.wireshark_config = "%s/.wireshark/esp_sa" % (os.environ['HOME'],)
        elif 'APPDATA' in os.environ:
            self.wireshark_config = "%s/Wireshark/esp_sa" % (os.environ['APPDATA'],)
        else:
            self.wireshark_config = None
            if self.debug >= 1:
                print("DEBUG: unknown wireshark esp config file, ignoring")
    
    def find_tunnels(self) -> None:
        """
        Finds IPSec tunnels in the source file.

        This method reads the source file line by line, looking for specific patterns
        that indicate IPSec tunnel configuration (SPI, ESP, keys). It populates
        the `self.tunnels` dictionary with the found information.
        """
        if not self.wireshark_config:
            return

        fd = open(self.sourcefile, "r")
        current = None
        
        fd_readBytes = 0
        # save the size
        try:
            fd.seek(0, os.SEEK_END)
            fd_size = fd.tell()
            fd.seek(0, os.SEEK_SET)
        except IOError:
            # can happen for fifo etc.
            # but in that case this whole part would not work anyway
            fd_size = 0


        while True:
            line = fd.readline()
            if len(line) == 0:
                break
            fd_readBytes += len(line)
            line = line.strip()
            ls = line.split()
        
            if len(ls) >= 1 and  "name=" in ls[0][:5] and ls[1] == "ver=1":
                current = ls[0][5:]
                while current in self.tunnels:
                    # different phase1s can have the phase2s with the same name
                    # - if it happens, just rename it
                    newcurrent = "%s_%i" % (current, random.random()*1000,)
                    current = newcurrent
        
                self.tunnels[current] = {}
                self.tunnels[current]['src'] = ls[3].split("->")[0].split(":")[0]
                self.tunnels[current]['dst'] = ls[3].split("->")[1].split(":")[0]
            
            if len(ls) >= 1 and ls[0] in ("dec:", "enc:"):
                direction = ls[0][:3]
        
                # first line is encryption
                if "spi=" != ls[1][:4]:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (spi)" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
                else:
                    spi = ls[1][4:]
        
                if "esp=" != ls[2][:4]:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (esp)\n" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
                else:
                    esp = ls[2][4:]
        
                if "key=" != ls[3][:4]:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (keylength)\n" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
                else:
                    keylength = ls[3][4:]
        
                try:
                    key = ls[4]
                except:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (key)\n" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
        
                # next line should be authentication
                auth = fd.readline().strip().split()
                if "ah=" != auth[0][:3]:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (ah)\n" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
                else:
                    authalg = auth[0][3:]
        
                if "key=" != auth[1][:4]:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (authkeylength)\n" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
                else:
                    authkeylength = auth[1][4:]
            
                try:
                    authkey = auth[2]
                except:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (authkey)\n" % (direction, current,))
                    self.tunnels[current]['ignore'] = True
        
                self.tunnels[current][direction] = {}
                self.tunnels[current][direction]["spi"] = spi
                self.tunnels[current][direction]["alg"] = esp
                self.tunnels[current][direction]["keylength"] = keylength
                self.tunnels[current][direction]["key"] = key
                self.tunnels[current][direction]["authalg"] = authalg
                self.tunnels[current][direction]["authkeylength"] = authkeylength
                self.tunnels[current][direction]["authkey"] = authkey


            if self.show_progress:
                progress_current = fd_readBytes * 100 / fd_size
                if 'progress_last' not in vars():
                    progress_last = None
                if progress_current != progress_last:
                    sys.stdout.write("PROGRESS: ipsec: %3i %%\r" % (progress_current,))
                    sys.stdout.flush()
                    progress_last = progress_current

        fd.close()

    def configure_wireshark(self) -> None:
        """
        Updates the Wireshark configuration file with found tunnels.

        This method iterates through the found tunnels and appends their configuration
        to the Wireshark `esp_sa` file, enabling Wireshark to decrypt the ESP packets.
        """
        outfile = self.wireshark_config
        if not outfile:
            return

        for tunnel in list(self.tunnels.keys()):
            if 'ignore' in self.tunnels[tunnel] and self.tunnels[tunnel]['ignore']:
                # there was something wrong with this tunnel...
                continue

            for direction in ("enc", "dec",):
                # cyphers
                cipher = (self.tunnels[tunnel][direction]['alg'], self.tunnels[tunnel][direction]['keylength'])
                if cipher not in self.cipher_map:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown cipher (%s, %s)\n" % (direction, tunnel, cipher[0], cipher[1],))
                    continue
                else:
                    ws_alg = self.cipher_map[cipher]
        
                # hashes
                hashish = (self.tunnels[tunnel][direction]['authalg'], self.tunnels[tunnel][direction]['authkeylength'])
                if hashish not in self.hash_map:
                    print("WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown hash (%s, %s)\n" % (direction, tunnel, hashish[0], hashish[1],))
                    continue
                else:
                    ws_authalg = self.hash_map[hashish]

                # we need to use the right direction, otherwise wireshark would not recognize it	
                if direction == 'enc':
                    dirpart = '"%s","%s"' % (self.tunnels[tunnel]['src'], self.tunnels[tunnel]['dst'],)
                elif direction == 'dec':
                    dirpart = '"%s","%s"' % (self.tunnels[tunnel]['dst'], self.tunnels[tunnel]['src'],)
                else:
                    dirpart = "error_that_never_happens"
                    
                outfd = open(outfile, "a")
                outfd.write('"IPv4",%s,"0x%s","%s","0x%s","%s","0x%s"\n' % (
                    dirpart,
                    self.tunnels[tunnel][direction]['spi'],
                    ws_alg,
                    self.tunnels[tunnel][direction]['key'],
                    ws_authalg,
                    self.tunnels[tunnel][direction]['authkey'],
                    ))
                outfd.close()
