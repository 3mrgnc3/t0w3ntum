#!/usr/bin/python
'''
Full port scans and port enumeration for the masses!
@T0w3ntum
'''
import sys, re, os, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser
from libnmap.parser import NmapParser, NmapParserException
from libnmap.process import NmapProcess



# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)

def get_ports(nmap_report):
    port_list = []
    for host in nmap_report.hosts:
        for serv in host.services:
            port_list.append(serv.port)
    ports = ",".join(map(str,port_list))
    print "[+] These are the open ports: %s" % (ports)
    return ports;

if __name__ == "__main__":
    # Set up arguments
    usage = '%prog -H HOST_IP'
    parser = OptionParser(usage=usage)
    parser.add_option('-H', '--host', type='string', action='store', dest='target_host', help='Target Host IP')
    parser.add_option('-i', '--intense', action='store_true', dest='intense', help='Perform further enumeration tasks on found services')
    (options, args) = parser.parse_args()
    IP = options.target_host
    if options.target_host is None:
        print "Missing host\n"
        parser.print_help()
        exit(-1)

    options = "-T4 --open --min-rate=400 -p-"
    print "[+] Perorming quick full port scan on %s" % (IP)
    report = do_scan(IP, options)
    if report:
	print_scan(report)
    else:
	print("No results returned")

    # Send report into get_ports
    print "[+] Identified open ports. Now performing intense scan"
    ports = get_ports(report)
    options = "-sT -A -p %s" % (ports)
    report = do_scan(IP, options)

    if report:
	print_scan(report)
    else:
	print("No results returned")
    
    if options.intense is not None:
        do_intense(ports)



