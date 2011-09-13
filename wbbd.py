#!/usr/bin/python

#Imports
from optparse import OptionParser
import subprocess
import urllib2
import sys
import os
import re

def validateParameters(options):
    """
    Who needs documentation
    TODO: Add some...
    """

    #options.identity should be a valid file
    if os.path.isfile(options.identity):
        try:
            f = open(options.identity, "r")
        except IOError as err:
            print "Could not open the identity file %s for reading, exiting." % options.identity
            sys.exit(1)
        finally:
            f.close()
    else:
        print "Could not find the identity file %s, exiting." % options.identity
        sys.exit(1)

    #options.rport, options.lport, and options.port should be numeric
    if not options.rport.isdigit() or not options.lport.isdigit() or not options.port.isdigit():
        print "rport:%s lport:%s port:%s" % (options.rport, options.lport, options.port)
        print "rport, lport, and port options must all be numbers, exiting."
        sys.exit(1)

    #options.host should be an IP or a hostname
    validIpAddressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    validHostnameRegex = "^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"

    if not re.match(validIpAddressRegex, options.host) and  not re.match(validHostnameRegex, options.host):
        print "Supplied host: %s" % options.host
        print "Host appears to not be a valid host, exiting."
        sys.exit(1)

    #If we made it this far, we can return True
    return True
    
def popShell(identity, rport, lport, port, username, host):
    """
    Who needs documentation...
    TODO: Add some...
    """

    #TODO: Probably should not redirect stdout and stderr so forcefully. Let Popen handle it.
    cmd = "ssh -N -i %s -R %s:127.0.0.1:%s -p %s -l %s %s  > /dev/null 2>&1 &" % \
        (identity, rport, lport, port, username, host)

    x = subprocess.Popen(cmd, shell=True)

def fetchPage(url):
    """
    Who needs documentation...
    TODO: Add some...
    """
    
    #TODO: Add some URL validation. Mo' regex...
    try:
        page = urllib2.urlopen(url)
    
    except ValueError as err:
        #User gave a funky URL...
        print err
        print "You gave a weird url: %s" % url
        print "Exiting."
        sys.exit(1)

    except urllib2.HTTPError as err:
        #We got an HTTP Error, such as a 404 Not Found...
        return False
    
    else:
        #No error, so check and see if we got "good" results
        if page:
            return True

if __name__ == "__main__":
    
    #Handle all the command line args...
    parser = OptionParser()

    parser.add_option("-i", "--identity", action = "store", type = "string", \
                          dest = "identity", help = "SSH identity file (full path helps)", default = None)

    parser.add_option("-r", "--rport", action = "store", type = "string", \
                          dest = "rport", help = "Remote port to listen on and forward back to lport", \
                          default = "12345")

    parser.add_option("-L", "--lport", action = "store", type = "string", \
                          dest = "lport", help = "Local port to forward back to", default = "22")

    parser.add_option("-p", "--port", action = "store", type = "string", \
                          dest = "port", help = "SSH port for initial outbound connect", default = "22")

    parser.add_option("-l", "--user", action = "store", type = "string", dest = "user", \
                           help = "SSH User name", default = None)

    parser.add_option("-H", "--host", action = "store", type = "string", dest = "host", \
                          help = "Remote hostname or ip", default = None)

    parser.add_option("-u", "--url", action = "store", type = "string", dest = "url", \
                          help = "URL to fetch and use as switch for running the SSH session", \
                          default = None)
    
    (options, args) = parser.parse_args()

    #Validate basic args
    if not options.url:
        print "URL is a mandatory option!"
        print "See help for more information. \n"
        print options.help

    elif not options.identity or not options.user or not options.host:
        print "Identity, user, and host are currently all mandatory options!"
        print "See help for more information.\n"
        print options.help

    else:
        #Then really validate some args for data
        if validateParameters(options):
            print "Parameters look good, fetching url..."
            
            if fetchPage(options.url):
                print "Got the page, trying to SSH..."
                popShell(options.identity, options.rport, options.lport, \
                             options.port, options.user, options.host)

            else:
                print "No page to fetch, exiting without trying to SSH..."
                sys.exit(0)
