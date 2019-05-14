
import time
import pyfiglet

result = pyfiglet.figlet_format("WEB SCANNER")
print(result)
# Python program to print
# red text with green background

black='\033[30m'
red='\033[31m'
green='\033[32m'
orange='\033[33m'
blue='\033[34m'
purple='\033[35m'
cyan='\033[36m'
lightgrey='\033[37m'
darkgrey='\033[90m'
lightred='\033[91m'
lightgreen='\033[92m'
White='\033[0;37m'


#BOLD
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'        # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'     # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White


#underline
UBlue='\033[4;34m'        # Blue
UPurple='\033[4;35m'


cstr=BCyan+'TEAMS MEMBERS NAME :'+White
#print()
#print(' ')
print (cstr.center(44))
rstr=blue+'Aditya Gupta'
print(rstr.center(40))
rstr1=blue+'Ashish Totla'
print(rstr1.center(40))
rstr2=blue+'Prabhat Sharma'+White
print(rstr2.center(48))
print(' ')
print(UPurple+"Enter the funtionality you want to run "+White)
print(' ')
print(BWhite+"WAF Detection : 1")
print(' ')
print("Mail Server Misconfiguration : 2")
print(' ')
print("Check Security Headers : 3")
print(' ')
print("OS Detection : 4")
print(' ')
choice=input(BWhite+"Enter your choice  "+White)

if choice == '1':
    import urllib.request
    import sys

 #   from colorama import init
 #   init(strip=not sys.stdout.isatty()) # strip colors if stdout is redirected
    #from termcolor import cprint
 #   from pyfiglet import figlet_format

    #cprint(figlet_format('missile!', font='starwars'),
     #      'yellow', 'on_red', attrs=['bold'])

    x=input('enter the url ')
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) '
                          'AppleWebKit/537.11 (KHTML, like Gecko) '
                          'Chrome/23.0.1271.64 Safari/537.11',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
            'Accept-Encoding': 'none',
            'Accept-Language': 'en-US,en;q=0.8',
            'Connection': 'keep-alive'}
    req = urllib.request.Request(x,headers=hdr)
    res = urllib.request.urlopen(req)
    #time.sleep(5)
    #print(res.info())
    res.close();
    server=res.info().get('Server')
    cookies=res.info().get('Set-Cookie')
    akamai=res.info().get('X-akamai-transformed')
    varnish1=res.info().get('Via')
    varnish2=res.info().get('X-Varnish')
    anquanbao=res.info().get('X-Powered-By-Anquanbao')
    aws1=res.info().get('X-Cache')
    Powercdn=res.info().get('X-PowerCDN-Error')
    xlabs=res.info().get('Secured')

    #print (akamai)

    #Cloudflare
    print('Scanning For Cloud Flare')
    time.sleep(2)
    if server is not None:
        if server=='cloudflare':
            print (BGreen+'cloudflare WAF is detected'+White)


    elif cookies is not None:
        if cookies.find('__cfduid')!= -1:
            print (BGreen+'cloudflare WAF is detected'+White)
        else:
            print(BRed+'Not Found'+White)
    #Akamai
    print('Scanning For Akammi')
    time.sleep(2)
    if akamai is not None:
        print ('Akamai Kona WAF detected')
    else:
        print(BRed+'Akamai not found'+White)

    #Varnish
    print('Scanning For Varnish')
    time.sleep(2)
    if server is not None:
        if server=='Varnish':
            print (BGreen+'Varnish WAF is detected'+White)
        else:
            print(BRed+'Varnish WAF not found'+White)
    elif varnish1 is not None:
        if varnish1.find('Varnish')!= -1:
            print (BGreen+'Varnish WAF is detected'+White)
        else:
            print(BRed+'Varnish WAF not found'+White)
    elif varnish2 is not None:
        print (BGreen+'Varnish WAF is detected'+White)


    print('Scanning For Citrix Netscaler')
    time.sleep(2)
    if cookies is not None:
        if cookies.find('ns_af')!= -1:
            print (BGreen+'Citrix Netscaler WAF is detected'+White)
        else:
            print(BRed+'Citrix Netscaler WAF is not detected'+White)

    print('Scanning For Anquanbao')
    time.sleep(2)
    if server is not None:
        if server=='ASERVER':
            print ('Anquanbao WAF is detected')
        else:
            print(BRed+' Anquanbao WAF not found'+White)

    elif anquanbao is not None:
        print ('Anquanbao WAF is detected')

    print('Scanning For Cloudfront')
    time.sleep(2)
    if aws1 is not None:
        if aws1.find('Cloudfront')!= -1:
            print ('cloudfront WAF is detected')
        else:
            print(BRed+'Cloudfront WAF not found'+White)
    elif varnish1 is not None:
        if varnish1.find('Cloudfront')!= -1:
            print ('Cloudfront WAF is detected')
        else:
            print(BRed+'Cloudfront WAF not found'+White)
    else:
        print(BRed+'CloudFront WAF not found'+White)

    print('Scanning For PowerCDN')
    time.sleep(2)
    if server is not None:
       if server=='PowerCDN':
           print ('Power CDN WAF is detected')
       else:
            print(BRed+'PowerCDN WAF not found'+White)
    elif Powercdn is not None:
        print ('Power CDN WAF is detected')
    print('Scanning For Safedog')
    time.sleep(2)
    if server is not None:
        if server=='Safedog WAF':
            print ('Safedog WAF is detected')
        else:
            print(BRed+'Safedog WAF not found'+White)
    elif cookies is not None:
        if cookies.find('safedog-flow-item')!= -1:
            print ('Safedog WAF is detected')
        else:
            print(BRed+'Safedog WAF not found'+White)
    print('Scanning For XLabs')
    time.sleep(2)
    if server is not None:
        if server=='XLabs WAF':
            print ('XLabs WAF is detected')
        else:
            print(BRed+'XLabs WAF not found'+White)
    elif xlabs is not None:
        if xlabs.find('XLabs')!= -1:
            print ('XLabs WAF is detected')
        else:
           print(BRed+'XLabs WAF not found'+White)

elif choice == '2':
    import dns.resolver #import the module
    import sys
    myResolver = dns.resolver.Resolver() #create a new instance named 'myResolver'
#print("Enter the url")
    x=input("Enter URL here  https://www.")


    try:
        myAnswers = myResolver.query(x, 'TXT') #Lookup the 'TXT' record(s) for google.com
    except Exception as e:
        print("vulnerable")
        sys.exit()
    name=None
    for rdata in myAnswers: #for each response
        if 'spf1' in str(rdata):
         name=rdata
         print (rdata) #print the data
    print(type(name))
    name = str(name)

#name = name.split()
    name = str(name)


    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    if name is not None:
        if "spf1" in name:
            if "-" in name:
                time.sleep(2)
                print( BOLD+GREEN+'SPF RECORD WITH HARDFAIL')
                print('Domain is Safe')
            elif "~" in name:
                time.sleep(2)
                print(BOLD+RED+'SPF RECORD WITH SOFTFAIL')
                print('Domain is UnSafe')

            elif "?" in name:
                time.sleep(2)
                print(BOLD+RED+'SPF RECORD WITH NEUTRAL')
                print('Domain is unsafe')
        else:
            time.sleep(2)
            print("NO")

elif choice=='3':
    import http.client  ##This module defines classes which implement the client side of the HTTP and HTTPS protocols.
    import argparse
    import socket
    import ssl
    import sys
    import re

    from urllib.parse import urlparse  ##Parse a URL into six components, returning a 6-item

    class SecurityHeaders():

        def evaluate_warn(self, header, contents): ##A function in Python is defined by a def statement.
            """ Risk evaluation function.
            Set header warning flag (1/0) according to its contents.
            Args:
                header (str): HTTP header name in lower-case
                contents (str): Header contents (value)
            """
            warn = 1

            if header == 'x-frame-options':
                if contents.lower() in ['deny', 'sameorigin']:
                    warn = 0
                else:
                    warn = 1

            if header == 'strict-transport-security':
               if contents=='max-age=31536000':
                   warn = 0


            if header == 'content-security-policy':
              if contents=='script-src self':
                warn = 0


            if header == 'access-control-allow-origin':
                if contents == '*':
                    warn = 1
                else:
                    warn = 0

            if header.lower() == 'x-xss-protection':
                if contents.lower() in ['1', '1; mode=block']:
                    warn = 0
                else:
                    warn = 1

            if header == 'x-content-type-options':
                if contents.lower() == 'nosniff':
                    warn = 0
                else:
                    warn =1



            return {'defined': True, 'warn': warn, 'contents': contents}





        def check_headers(self, url, follow_redirects = 0):
            """ Make the HTTP request and check if any of the pre-defined
            headers exists.
            Args:
            """

            """ Default return array """
            retval = {
                'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
                'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
                'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
                'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
                'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''},


            }

            parsed = urlparse(url)
            protocol = parsed[0]
            hostname = parsed[1]
            path = parsed[2]
            if (protocol == 'http'):
                conn = http.client.HTTPConnection(hostname)
            elif (protocol == 'https'):
                    # on error, retry without verifying cert
                    # in this context, we're not really interested in cert validity
                    ctx = ssl._create_stdlib_context()
                    conn = http.client.HTTPSConnection(hostname, context = ctx )
            else:
                """ Unknown protocol scheme """
                return {}

            try:
                conn.request('HEAD', path)
                res = conn.getresponse()
                headers = res.getheaders()

            except socket.gaierror:
                print('HTTP request failed')
                return False

            """ Follow redirect """
            if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
                for header in headers:
                    if (header[0].lower() == 'location'):
                        redirect_url = header[1]
                        if not re.match('^https?://', redirect_url):
                            redirect_url = protocol + '://' + hostname + redirect_url
                        return self.check_headers(redirect_url, follow_redirects - 1)

            """ Loop through headers and evaluate the risk """
            for header in headers:

                #set to lowercase before the check
                headerAct = header[0].lower()

                if (headerAct in retval):
                    retval[headerAct] = self.evaluate_warn(headerAct, header[1])

            return retval

    if __name__ == "__main__":

   #     parser = argparse.ArgumentParser(description='Check HTTP security headers', \
   #         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
   #     parser.add_argument('url', metavar='URL', type=str, help='Target URL')
   #     parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int, help='Max redirects, set 0 to disable')
   #     args = parser.parse_args()
   #     url = args.url
        BWhite='\033[1;37m'       # White
        White='\033[0;37m'
        url=input(BWhite+"Enter the url  "+White)
        # redirects = args.max_redirects
        redirects = 2

     # redirects = args.max_redirects

        foo = SecurityHeaders()

        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url # default to http if scheme not provided


        headers = foo.check_headers(url, redirects)

        if not headers:
            print ("Failed to fetch headers, exiting...")
            sys.exit(1)

        okColor = '\033[1m'    #for bold
        warnColor = "\033[31m" #
        endColor = '\033[0m'
        for header, value in headers.items():
            if value['warn'] == 1:
                if value['defined'] == False:
                    print('Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]')
                    time.sleep(2)
                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')
                    time.sleep(2)
            elif value['warn'] == 0:
                if value['defined'] == False:
                    print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
                    time.sleep(2)
                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + okColor + 'OK' + endColor + ' ]')
                    time.sleep(2)

elif choice=='4':
    import requests
    import urllib.request
    x=input('enter the url')
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
           'Accept-Encoding': 'none',
           'Accept-Language': 'en-US,en;q=0.8',
           'Connection': 'keep-alive'}
    req = urllib.request.Request(x,headers=hdr)
    res = urllib.request.urlopen(req)
    print(res.info())
    res.close();
    server=res.info().get('Server')
    cookies=res.info().get('Set-Cookie')
    power=res.info().get('X-Powered-By')

    # Microsoft Server
    if server is not None:
        if server.find('Microsoft')!= -1:
            print (server)
    elif cookies is not None:
        if cookies.find('ASP.NET_SessionId')!= -1:
            print ('This is a Microsoft server')
    elif power is not None:
        if power.find('ASP.NET')!= -1:
            print ('This is a Microsoft server')

    if server is not None:
        if server.find('Ubuntu')!= -1:
            print (server)
    a=x+'/arecueunf/asdfenfdaos'
    r = requests.get(a)
    #print(r.content)
    a='The requested URL'

    if r is not None:
        if r.text.find(a)!=-1:
            print('This is a Linux')
