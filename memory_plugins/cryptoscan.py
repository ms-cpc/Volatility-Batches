# CryptoScanner
# Copyright (C) 2008 Jesse Kornblum
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Jesse Kornblum
@license:      GNU General Public License 2.0 or later
@contact:      research@jessekornblum.com
@organization: 
"""

import string

from vutils import *
from forensics.win32.scan2 import *


def is_printable(s):
    for pos in range(0,len(s)):
        if not s[pos] in string.printable:
            return False
    return True

def all_zero_chars(s):
    for pos in range(0,len(s)):
        if not s[pos] == '\x00':
            return False
    return True

# The window size needs to accomidate the passphrase, the passphrase
# length, and the magic value 
TC_PASSWORD_LENGTH = 64
TC_WINDOW_SIZE     = TC_PASSWORD_LENGTH + 8

class TrueCryptScanner(GenMemScanObject):
    """
    Scan for TrueCrypt passphrases using the method described
    in Brian Kaplan's thesis, 'RAM is Key, Extracting Disk
    Encryption Keys From Volatile Memory', pages 22-23.
    http://www.andrew.cmu.edu/user/bfkaplan/
    
    Passphrases are stored in a structure containing a magic
    value (0x7d0), a passphrase length, and then 64 bytes of
    passphrase data. The data must contain exactly length ASCII
    characters and all remaining bytes must be zeros.
    """
    
    def __init__(self, addr_space):
        GenMemScanObject.__init__(self, addr_space)
        
    class Scan(SlidingMemoryScanner):
        def __init__(self, poffset, outer):
            SlidingMemoryScanner.__init__(self, poffset, outer, TC_WINDOW_SIZE)

        def test_passphrase(self, buffer, offset):
            if offset % 4 != 0:
                return
            
            # Extract the supposed length of the passphrase
            # and what should be the passphrase data
            length,raw_data = unpack("<L64s", buffer)
            if length > TC_PASSWORD_LENGTH or length == 0:
                return 

            passphrase = raw_data[:length]

            if not is_printable(passphrase) or \
                   not all_zero_chars(raw_data[length:]):
                return

            print "Found TrueCrypt passphrase \"%s\" at 0x%x" \
                      % (passphrase, offset)

                
        def process_buffer(self, buf, poffset, metadata = None):
            found = 0
            while 1:
                found = buf.find("\xd0\x07\x00\x00", found + 1)

                if found >= 0:
                    # Avoid going beyond the end of the buffer
                    if not (found + TC_WINDOW_SIZE > len(buf)):

                        # There's no need to pass the magic value
                        self.test_passphrase(buf[found+4:found+TC_WINDOW_SIZE],
                                             poffset+found)
                else:
                    break
                



class cryptoscan(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Jesse Kornblum'
    meta_info['copyright'] = 'Copyright (C) 2008 Jesse Kornblum'
    meta_info['contact'] = 'research@jessekornblum.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://jessekornblum.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    # This module makes use of the standard parser. Thus it is not 
    # necessary to override the forensics.commands.command.parser() method.
    # The standard parser provides the following command line options:
    #    '-f', '--file', '(required) Image file'
    #    '-b', '--base', '(optional) Physical offset (in hex) of DTB'
    #    '-t', '--type', '(optional) Identify the image type'



    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Find TrueCrypt passphrases"
    

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):
        scanners = []
        if self.opts.filename is None or \
               not os.path.isfile(self.opts.filename):
            self.op.error("File is required")
        else:
            filename = self.opts.filename

        try:
            addr_space = FileAddressSpace(filename, fast=True)
        except:
            self.op.error("Unable to open image file %s" % (filename))

        scanners.append(TrueCryptScanner(addr_space))

        scan_addr_space(addr_space, scanners)
