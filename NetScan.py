#!/usr/bin/env python


#MODULES
import subprocess as sp
import scapy.all as scapy
import re
import optparse
import time


#TITLE
sp.call("clear;figlet -f standard 'NET SCANNER'",shell=True)


#WHILE !EXCEPTIONS
try:

    #GLOBAL VARIABLES
    BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END, BOLD, UNDERLINE, PURPLE, CYAN, DARKCYAN = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m', '\033[4m', '\033[95m', '\033[96m', '\033[36m'

    #CLASS-METHODS
    class NetScanner:
        def __init__(self):
            self.iprange = raw_input("Enter The Subnet ID of Your IP (Ex - 192.168.0 is the subnet id of 192.168.0.13 )\n>>")
            self.interface = raw_input("Enter The Name of Network Interface to Scan (Ex - eth0 or wlan0)\n>>")
            self.scanned_ips = []
            self.scanned_macs = []
            self.scanned_vendors = []
            if ".1/24" not in self.iprange:
                self.iprange += ".1/24"
            self.ScanNetwork(self.iprange,self.interface)

        def ScanNetwork(self,iprange,interface):
            print(YELLOW+"\n[+] Scanning Network for Clients\n"+END)
            self.netdiscover_result = sp.check_output("netdiscover -P -i "+interface+" -r "+iprange,shell=True)
            self.AnalyzeResult(self.netdiscover_result)

        def AnalyzeResult(self,result):
            self.pattern_for_extracting_ip = "(\d*\.\d*\.\d*\.\d*)(?:\s)"
            self.pattern_for_extracting_mac = "(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)"
            self.pattern_for_extracting_vendor = "(?:\w\w:\w\w:\w\w:\w\w:\w\w:\w\w\s\s\s\s\s\s\d\s\s\s\s\s\s\d\d\s)(.*)"
            self.scanned_ips = self.RegexFindAll(self.pattern_for_extracting_ip,self.netdiscover_result)
            self.scanned_macs = self.RegexFindAll(self.pattern_for_extracting_mac,self.netdiscover_result)
            self.scanned_vendors = self.RegexFindAll(self.pattern_for_extracting_vendor,self.netdiscover_result)
            self.DisplayResult()

        def DisplayResult(self):
            print(GREEN+"[+] Available Clients on the Network\n"+END)
            print("--------------------------------------------------------------------------\n"+RED+"IP Addresses\t\tMAC Addresses\t\t\tVendor/OS/Manufacturer"+END+"\n--------------------------------------------------------------------------")
            self.list_length = len(self.scanned_ips)
            self.count = 0
            while self.count < self.list_length:
                print(CYAN+self.scanned_ips[self.count]+"\t\t"+self.scanned_macs[self.count]+"\t\t"+self.scanned_vendors[self.count]+END+"\n--------------------------------------------------------------------------\n")
                self.count += 1


        def RegexFindAll(self,pattern,string):
            self.result_after_regex = re.findall(pattern,string)
            self.elements_list = []
            for self.elements in self.result_after_regex:
                self.elements_list.append(self.elements)
            return self.elements_list

    Ns = NetScanner()

#EXCEPTION HANDLING
except KeyboardInterrupt:
    print(RED+"\n\n[-] KeyboardInterrupt Occured!!!\nExiting ...\n"+END)
    sp.call("rm scan_result.txt",shell=True)
    quit()
