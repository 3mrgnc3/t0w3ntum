#!/usr/bin/python
'''
Full port scans and port enumeration for the masses!
@T0w3ntum
'''
import sys, re, os
import xml.etree.ElementTree as ET
from optparse import OptionParser
from libnmap.parser import NmapParser

# Set up arguments
usage = '%prog -h HOST_IP'
parser = OptionParser(usage=usage)
parser.add_option('-H', '--host', type='string', action='store', dest='target_host', help='Target Host IP')
(options, args) = parser.parse_args()

IP = options.target_host


def nmap_full(host):
  print "[+] Performing full port scan"
  string = 'nmap --open -T4 --min-rate=400 -p- -oX %s.xml %s >/dev/null' % (host, host)
  os.system(string)
  return;

def nmap_intense(ip,ports):
  ports = map(str, ports)
  p = ",".join(ports)
  print "[+] Doing full port scan on %s" % (ports)
  string = 'nmap -sV -A -p %s -oX %s-full.xml %s > /dev/null' % (p, ip, ip)
  os.system(string)
  return;

def nmap_report_quick(IP):
  string = '%s.xml' % (IP)

  nmap_report = NmapParser.parse_fromfile(string)
  list_ports = []
  for _host in nmap_report.hosts:
    host = ', '.join(_host.hostnames)
    address = (_host.address)
    print "[+] Full scan complete on following hosts"
    print "[Hostname] ", host, "--", address
    for _services in _host.services:
      print "[Open Port]", _services.port, "--", _services.protocol, "--", _services.service
      list_ports.append(_services.port)
  nmap_intense(IP,list_ports)
      

nmap_full(IP)
nmap_report_quick(IP)
	
	


