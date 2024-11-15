import scapy.all as scapy
import re, argparse, sys, os, ipaddress

#SCAPY WHO_HAS PACKET
#BROADCAST ADRESS
#SEND = srp()

parser = argparse.OptionParser()
parser.add_argument('-i', '--ip', dest="ip", help="Type the IP u want to scan")
parser.add_argument('-a', '--aggressive', dest="aggressive", help="Scanning deeper and take more time")
parser.add_argument('-o', '--output', dest="output", help="Output IP Addresses & MAC Addresses in a file")
options  = parser.parse_args()

tablist = []
dico = {}

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_rb = broadcast/arp_req

    if options.aggressive is None:
        answered = scapy.srp(arp_rb, timeout=1)[0]
    elif options.aggressive == "1":
        answered = scapy.srp(arp_rb, timeout=3)[0]
    else:
        sys.exit('\n \033[91mAggressive option has to be 1 or Nothing\033[0m \n') 
    
    print("--------------------------------------------------------")
    print('IP\t\t\t\t MAC Address')
    print("--------------------------------------------------------")
    
    for a in answered:
        print(a[1].psrc, "\t\t\t",a[1].hwsrc)
        dico = {"IP": a[1].psrc, "MAC":a[1].hwsrc}
        tablist.append(dico)
        if options.output is None:
            pass
        else:
            file = open(f'{options.output}.txt', 'w')
            for e in tablist:
                file.writelines(f"{str(e)}\n")
            file.close()
            
    if options.output is None:
        pass
    else:
        print('\n\033[0;32mFile saved at \t',os.path.abspath(f'{options.output}.txt'))
        #print(a)

if options.ip is None:
    print('\n \033[91mPyNetScanner needs an IP to scan use --ip\033[0m \n')
    
    parser.print_help()
    sys.exit()
else:

    a = re.match(
    r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{2}", options.ip
    )
    b = re.match(
    r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", options.ip
    )

    if bool(a) == True or bool(b) == True:
        scan(options.ip)
    else:
        print('\n \033[91mInvalid IP Address or Range of IP Addresses')



