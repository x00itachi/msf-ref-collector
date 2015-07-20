## Metasploit References Collector
This is a small script which is used to collect all existing references(CVE, BID, OSVDB, etc..) from Metasploit Framework and create an organized CSV format.

### How-TO use it:
	1) Copy "pull-msf-refs.rb" script to local MSF installed machine
	2) Open msfconsole
	3) move to folder where above ruby file copied
	4) run "resource pull-msf-refs.rb" on msf console
		msf> resouce pull-msf-refs.rb
	5) Then it will generate msfrefs.csv file on same directory

### Output "msfrefs.csv" format:
	<exploit-name>,<ref1>;<ref2>;<ref3>;<ref4>;<ref5>
