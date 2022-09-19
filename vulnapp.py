
import argparse
import datetime
import locale
import os
import sys
import urllib
import time
from jinja2 import Environment, FileSystemLoader
import pdfkit

# Define arguments, errors, variables using argparse
parser = argparse.ArgumentParser(
    description='VulnAPP audit the security in the configuration files of your Cisco network devices, it brings you a report with the findings details and recommendations.')
parser.add_argument('-f', action="store", dest='file', help='Please type the configuration file that you want to scan.')
parser.add_argument('-c', action="store", dest='customer', help='Please type the name of the customer.')


args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = vars(args)

if args['file'] is None:
    print ("Please enter the hostgroup")
    sys.exit()
else:
    archivo = args['file']

if args['customer'] is None:
    print ("Please enter the start time using this format 30.8.2016")
    sys.exit()
else:
     customer= args['customer']




#get Date


def getDate():
    t= time.strftime("%d/%m/%Y")
    return t

#Function to get hostname
def gethostname(configfile):
    datafile = open(configfile)
    for line in datafile:
        if "hostname" in line:
            hostanme= line.replace('hostname ', '')
            return hostanme

name= str(gethostname('router.cfg'))


# Function To detect version
def getVersion(configfile):
    datafile = open(configfile)
    for line in datafile:
        if "version" in line:
            fversion= line.replace('version ', '')
            fversion= fversion.replace(')', '').replace("(", '')
            return fversion

#1
def EnablePassword(configfile):
    l = ["<!--", "-->"]
    datafile = open(configfile)
    for line in datafile:
        if "no enable password" in line:
            return l
        if "enable password" in line:
            return
    return l

#2
def RipEnabled(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    i=0
    for line in datafile:
        if "router rip" in line:
            i=i+1
        if  "version 2"  in line:
            if i == 1:
              return l
    if i == 1 :
       return
    else:
        return l


#3
def ClearTextSNMP(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if ("snmp-server")  in line:
             if ("v1") in line:
                return
             if ("v2c") in line:
                return
             if ("version 2c") in line:
                return
             if ("version 3") in line:
                return  l
             if ("v3") in line:
                return  l
             else:
                 return l

#4
def PortAuxEnabled(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    i=0
    for line in datafile:
        if "line aux 0" in line:
            i=i+1
        if  "no exec"   in line:
            if i == 1:
               return l
        if "line vty 0 4" in line:
            if i == 1:
               break
    if i == 1 :
       return

#5
def DefaultSNMPcommunity(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if ("snmp-server") in line:
            if ("public") in line:
                return
            if ("private") in line:
                return
    return l
#6
def LoginPasswordLookout(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if "aaa local authentication attempts max-fail" in line:
            return l
    return

#7
def HTTPSessionTimeout(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if "no ip http server" in line:
            return  l
        else:
             if "ip http timeout-policy idle" in line:
                 return l
    return

#8
def InboundTCPkeepAlive(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if "service tcp-keepalives-in" in line:
            return l
    return

#9
def SyslogLogin(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if "no logging host" in line:
            return
        if "logging host" in line:
            return l
    return

#10
def Bannerlogin(configfile):
    datafile = open(configfile)
    l = ["<!--", "-->"]
    for line in datafile:
        if "banner login" in line:
            return l
        if "banner motd" in line:
            return l
    return

#11
def ICMPunreacheable(configfile):
    datafile = open(configfile)
    for line in datafile:
        if "no ip unreachables" in line:
            l = ["<!--", "-->"]
            return l
    return

#12
def UDPsmallservices(configfile):
    datafile = open(configfile)
    for line in datafile:
        if "no service udp-small-servers" in line:
            l = ["<!--", "-->"]
            return l
    print ("UDP Small Services Enabled")
    return


#13
def SNMPwriteAcess(configfile):
    l = ["<!--", "-->"]
    datafile = open(configfile)
    for line in datafile:
        if ("snmp-server") in line:
            if ("RW") in line:
                return
    return l

#14
def HTTPenabled(configfile):
    l = ["<!--", "-->"]
    datafile = open(configfile)
    for line in datafile:
        if "no ip http server" in line:
            return l
        else:
             if "ip http server" in line:
                 return

#15
def CDPenabled(configfile):
    l = ["<!--", "-->"]
    datafile = open(configfile)
    for line in datafile:
        if "no cdp run" in line:
            return l
        if "cdp run" in line:
            return
    return



Vuln1 = EnablePassword(archivo)
if Vuln1 != None:
    print ("Enable Password Configured: Bad security Cisco practice")

Vuln2 = RipEnabled(archivo)
if Vuln2 != None:
    print ("RIP version 1 enabled")

Vuln3 = ClearTextSNMP(archivo)
if Vuln3 != None:
    print ("Clear-Text SNMP In Use")

Vuln4 = PortAuxEnabled(archivo)
if Vuln4 != None:
    print ("AUX Port Not Disabled")

Vuln5 = DefaultSNMPcommunity(archivo)
if Vuln5 != None:
    print ("Default SNMP community string")

Vuln6 = LoginPasswordLookout(archivo)
if Vuln6 != None:
    print ("Login Password Retry Lockout")

Vuln7 = HTTPSessionTimeout(archivo)
if Vuln7 != None:
    print ("No HTTP Server Session Timeout")


Vuln8 = InboundTCPkeepAlive(archivo)
if Vuln8 != None:
    print ("No Inbound TCP Connection Keep-Alives")

Vuln9 = SyslogLogin(archivo)
if Vuln9 != None:
    print ("Syslog Logging Not Enabled")


Vuln10 = Bannerlogin(archivo)
if Vuln10 != None:
    print ("No Warning In Pre-Logon Banner")

Vuln11 = ICMPunreacheable(archivo)
if Vuln11 != None:
    print ("ICMP unreacheable")

Vuln12 = UDPsmallservices(archivo)
if Vuln12 != None:
    print ("UDP Small Services Enabled")

Vuln13 = SNMPwriteAcess(archivo)
if Vuln13 != None:
    print ("SNMP Write Access Enabled")

Vuln14 = HTTPenabled(archivo)
if Vuln14 != None:
    print ("Clear Text HTTP Service Enabled")

Vuln15 = CDPenabled(archivo)
if Vuln15 != None:
    print ("CDP Was Enabled")

version = float(getVersion(archivo))


l = ["<!--", "-->"]

Vuln16 = l
if version < 15.3:
    print ("Vulnerable to SNMP Remote Code Execution Vulnerabilities in Cisco IOS and IOS XE Software")
    Vuln16= ""

Vuln17 = l
Vuln18 = l
if version < 15.2:
    print ("Vulnerable to Cisco IOS Software and IOS XE Software TCP Packet Memory Leak Vulnerability")
    Vuln17= ""
    print ("Multiple Vulnerabilities in ntpd (April 2015) Affecting Cisco Products")
    Vuln18 = ""

Vuln19 = l
if version < 12.420:
    print ("Vulnerable to Cisco IOS Software Multicast Network Time Protocol Denial of Service Vulnerability")
    Vuln19 = ""


Vuln20 = l
Vuln21 = l
if version < 12.423:
    print ("Vulnerable to Cisco IOS Software Tunnels Vulnerability")
    Vuln20 = ""
    print ("Cisco IOS Software Multiple Features Crafted UDP Packet Vulnerability")
    Vuln21 = ""

Vuln22 = l
if version < 12.419:
    print ("Cisco IOS Software Multiple Features IP Sockets Vulnerability")
    Vuln22 = ""


Vuln23 = l
if version < 12.425:
    print ("TCP State Manipulation Denial of Service Vulnerabilities in Multiple Cisco Products")
    Vuln23 = ""


Vuln24 = l
Vuln25 = l
if version < 12.246:
    print ("Multiple Multicast Vulnerabilities in Cisco IOS Software")
    Vuln24 = ""
    print ("Cisco IOS Next Hop Resolution Protocol Vulnerability")
    Vuln25 = ""

Vuln26 = l
if version < 12.324:
    print ("Multiple DLSw Denial of Service Vulnerabilities in Cisco IOS")
    Vuln26 = ""

Vuln27 = l
if version < 12.01:
    print ("Voice Vulnerabilities in Cisco IOS and Cisco Unified Communications Manager")
    Vuln27 = ""

Vuln28 = l
if version < 12.08:
    print ("Multiple Vulnerabilities in the IOS FTP Server")
    Vuln28 = ""

Vuln29 = l
if version < 12.237:
   print("Crafted IP Option Vulnerability")
   Vuln29 = ""

Vuln30 = l
if version < 12.234:
   print ("IOS HTTP Server Command Injection Vulnerability")
   Vuln30= ""


date=getDate()

# Define the template and variables to Jinga, finally render the variables in the html template
env = Environment(loader=FileSystemLoader('.'))
#template = env.get_template(a)
template = env.get_template("template.html")
template_vars = { "cliente" : customer, "os" : version, "date": date, "name": name, "Vuln1" : Vuln1, "Vuln2" : Vuln2, "Vuln3" : Vuln3, "Vuln4" : Vuln4, "Vuln6" : Vuln6, "Vuln5" : Vuln5, "Vuln7" : Vuln7, "Vuln8" : Vuln8, "Vuln9" : Vuln9, "Vuln10" : Vuln10, "Vuln11" : Vuln11, "Vuln12" : Vuln12,  "Vuln13" : Vuln13,  "Vuln14" : Vuln14,  "Vuln15" : Vuln15, "Vuln16" : Vuln16,  "Vuln17" : Vuln17,  "Vuln18" : Vuln18,  "Vuln19" : Vuln19,  "Vuln20" : Vuln20,"Vuln21" : Vuln21, "Vuln22" : Vuln22, "Vuln23" : Vuln23, "Vuln24" : Vuln24, "Vuln25" : Vuln25, "Vuln26" : Vuln26, "Vuln27" : Vuln27, "Vuln28" : Vuln28, "Vuln29" : Vuln29, "Vuln30" : Vuln30}
#template_vars = { "Vuln12" : Vuln12, "os" : version, "Vuln27" : Vuln27, "dates": t, "name": name}
html_out = template.render(template_vars)
f = open('report.html', 'wb')
f.write(html_out.encode('utf8') )
#f.write(html_out)
f.close()



options = {
    'page-size': 'Letter',
    'margin-top': '0.5in',
    'margin-right': '0.1in',
    'margin-bottom': '1.2in',
    'margin-left': '0.1in',
    'header-html': 'header.html',
    'header-spacing': '6',
    'footer-html': 'footer.html',
    'footer-spacing': '5',
}

final="VulnAPP_report_"+customer + ".pdf"
# convert html in pdf

pdfkit.from_file('report.html', final , options=options, verbose=True)
print ("printing report for " + customer +"....")