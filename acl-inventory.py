#!/usr/bin/env python3
import re
import argparse
import keyring
import getpass
import csv
from netmiko import Netmiko
from netmiko import NetMikoAuthenticationException

DEBUG=False

def dprint(line):
    if DEBUG:
        print(f"(d) {line}")

def get_acl_names(config):
    aclNames = [] 
    for line in config:
        if line.startswith('access-group'):
            name = (line.split()).pop(1)
            if not name in aclNames:
                aclNames.append(name)
    return(aclNames) 

def regexSearch (regex, string):
    search = (re.search(regex, string))
    if search: 
        data = search.group(0)
        return (True, data)
    else:
        return (False, "")
        
##########################################################################################################################
##########################################################################################################################

def main():
    VERSION = "0.1.1"
    KEYRING="acl-inventory"
    SAVE_CREDS_TO_KEYRING = True # Do we save all of our creds to the keyring by default?
    AUTO_KEYCHAIN = True # Automagicallu try the keychain if no password supplied

    print(f"\n\n# ACL Inventory v{VERSION} 2024 - Tony Mattke @tonhe")
    print("-----------------------------------------------------------\n")

    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(prog="python3 acl-inventory.py", 
                                     description="Inventory of ACL configurations on Cisco ASA")
    parser.add_argument("host", help="Hostname or IP of the ASA", default="", nargs="*")
    parser.add_argument("-u", "--user", dest="user", help="User ID for login", default="")
    parser.add_argument("-k", "--keyring", dest="keyring", help="Pull password from local keyring (by hostname)", action="store_true")
    parser.add_argument("-p", "--password", dest="change_password", help="Change keyring password via interactive login", action="store_true")
    parser.add_argument("-d", dest="debug", help=argparse.SUPPRESS, action="store_true")
    args = parser.parse_args()

    if args.debug:
        global DEBUG 
        DEBUG = True
        print(">Debug ON")

    hostname = ""
    if args.host:
        hostname = args.host[0]
    if not hostname:
        hostname = input("Enter the ASA Management IP/Hostname: ")
    if "@" in args.host: # for those that username@hostname
        username=args.host.split('@')[0]
        hostname=args.host.split('@')[1]
    dprint (hostname)

    username = False
    if args.user:
        username = args.user
    while not username:
        username = input('Username: ')
    dprint (username)

    password=""
    if (args.keyring or AUTO_KEYCHAIN) and not args.change_password:
        print("Pulling password from local keyring.")
        password=keyring.get_password(KEYRING, hostname)
        dprint (f"password=keyring.get_password({KEYRING}, {hostname} )")
        if not password:
            print(f"Password for {hostname} not found in keyring\n")
    while not password: # Just in case we still don't have a password... 
        password = getpass.getpass('Password: ')

    notloggedin = True
    while notloggedin:
        try:
            print(f"Logging into {hostname}")
            ssh_connection = Netmiko(host=hostname, username=username, password=password, device_type='cisco_asa')
            notloggedin = False
        except NetMikoAuthenticationException as e: # Catch any authorization errors
            print ("\n!! Authorization Error\n")
            dprint (e)
            notloggedin = True
            password  = ""
            while not password: 
                password = getpass.getpass('Password: ')
        except Exception as e:                  # If login fails loops to begining displaying the error message
            print(e)
    
    if SAVE_CREDS_TO_KEYRING:
        keyring.set_password(KEYRING, hostname, password)

    ssh_connection.find_prompt()         # Expects to receive prompt back from the ASA
    ssh_connection.send_command('term pager 0')

    print("Retrieving list of access-lists...", end='')
    show_run = ssh_connection.send_command('show run access-group').split("\n")

    file = open("show_run.txt", "w")
    for line in show_run: 
        file.write(f"{line}\n")
    file.close()
    
    acl_names = get_acl_names(show_run)
    print(' done\n')

    FILENAME = "inventory.csv"
    acl_names = ["INSIDE-IN"] # used for testing purposes

    singlePortIdentifiers = ["eq", "lt", "gt", "neq"]
    skipWords = ["deny", "fqdn", "object", "inactive", "elements"]
    #skipWords = ["fqdn", "object", "inactive", "elements"]
    ticketRegex = r"(SCTASK|INC|CHG)\d+"
    tupleRegex = [r"^host ((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.\([-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)\)", # host 10.1.1.1 (foo.bar.com)
                  r"^host ((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}", # host 10.1.1.1
                  r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4} ((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}", # 10.1.1.1 255.255.255.255
                  "^any"] # any

    with open(FILENAME, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["ACL Name", "SNOW Record", "Line Number", "Action", "L4", "Source", "Destination", "Ports"])

        for aclName in acl_names:
            print(f"Retrieving ACL {aclName}...",end='', flush=True) 
            snowRecord = ""
            showAccessList =  ssh_connection.send_command(f'sh access-list {aclName}', read_timeout=90).split("\n") 
            print(" done")

            print(f"Running inventory scan on {aclName}...", end='')

            for line in showAccessList:
                dprint (line)
                if "remark" in line: # If this is a comment line, lets earch for a ticket number
                    searchBool, returnString = regexSearch(ticketRegex,line)
                    if searchBool: 
                        snowRecord = returnString
                        dprint (f"snowRecord {snowRecord}")
                    continue
                elif any(word in line for word in skipWords): # if any of these words are in the line, we skip it
                    dprint ("skipWord found in line")
                    continue
                else: 
                    # lets split the string into space segments and fill variables
                    line_number = line.split().pop(3) 
                    dprint(f"line number: {line_number}")
                    permitdeny = line.split().pop(5)
                    dprint(f"permitdeny: {permitdeny}")
                    protocol = line.split().pop(6)
                    dprint(f"protocol: {protocol}")
                    nextColumn = 7
                    dprint(f"nextColumn: {nextColumn}")
                    dprint (f"nextColumn Contents: {line.split().pop(nextColumn)}")

                    # Maximum length of destination is 3 "segments" 
                    sourceSegment = ' '.join(line.split()[nextColumn:nextColumn + 3])
                    dprint(f"sourceSegment: {sourceSegment}")
                    # Regex Search for the Source Information
                    for regexString in tupleRegex:
                        dprint(f"searching for {regexString}")
                        searchBool, returnString = regexSearch(regexString, sourceSegment)
                        if searchBool:
                            sourceInfo = returnString
                            dprint(f"sourceInfo: {sourceInfo}")
                            nextColumn = nextColumn + returnString.count(' ')  + 1 # don't hate me -- if we have 2 spaces, we advance a total of 3 columns
                            dprint(f"nextColumn: {nextColumn}")
                            break # Found it - break out of the for loop
                    
                    destinationSegment = ' '.join(line.split()[nextColumn:nextColumn + 3])
                    dprint(f"destinationSegment: {destinationSegment}")
                    for regexString in tupleRegex:
                        dprint(f"searching for {regexString}")
                        searchBool, returnString = regexSearch(regexString, destinationSegment)
                        if searchBool:
                            destinationInfo = returnString
                            dprint(f"destinationInfo: {destinationInfo}")
                            nextColumn = nextColumn + returnString.count(' ') + 1
                            dprint(f"nextColumn: {nextColumn}")
                            break

                    if protocol not in ["ip", "icmp"]: #eventually this needs to add ICMP types
                        dprint (f"nextColumn Contents: {line.split().pop(nextColumn)}")
                        if 'hitcnt' in line.split().pop(nextColumn): # are we matching all tcp/udp
                            portInfo = "all"
                        elif line.split().pop(nextColumn) in singlePortIdentifiers:
                            portInfo = line.split().pop(nextColumn + 1)
                        elif 'range' in line.split().pop(nextColumn):
                            portInfo = f'{line.split().pop(nextColumn + 1)}-{line.split().pop(nextColumn + 2)}'
                        else: 
                            portInfo = "error"
                    else:
                        portInfo = "all"

                    dprint(f"portInfo: {portInfo}")
                    rowData = [aclName, snowRecord, line_number, permitdeny, protocol, sourceInfo, destinationInfo, portInfo]
                    writer.writerow(rowData)
            print(" done\n")

    ssh_connection.disconnect()
    print(f"-Disconnecting from {hostname}")
    print("Inventory Complete - Exiting\n")

##########################################################################################################################
##########################################################################################################################

if __name__ == '__main__':
    main()
