#import urllib2
#import sys
#url = raw_input("Full url:")
#url.rstrip()
#header = urllib2.urlopen(url).info()
#print(str(header))
import urllib2
x=raw_input('enter the url')
hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'}
req = urllib2.Request(x,headers=hdr)
res = urllib2.urlopen(req)
print res.info()
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
if server is not None:
    if server=='cloudflare':
        print ('cloudflare WAF is detected')
elif cookies is not None:
    if cookies.find('__cfduid')!= -1:
        print ('cloudflare WAF is detected')

#Akamai
if akamai is not None:
    print ('Akamai Kona WAF detected')

#Varnish
if server is not None:
    if server=='Varnish':
        print ('Varnish WAF is detected')
elif varnish1 is not None:
    if varnish1.find('Varnish')!= -1:
        print ('Varnish WAF is detected')
elif varnish2 is not None:
    print ('Varnish WAF is detected')

if cookies is not None:
    if cookies.find('ns_af')!= -1:
        print ('Citrix Netscaler WAF is detected')

if server is not None:
    if server=='ASERVER':
        print ('Anquanbao WAF is detected')
elif anquanbao is not None:
    print ('Anquanbao WAF is detected')

if aws1 is not None:
    if aws1.find('Cloudfront')!= -1:
        print ('cloudfront WAF is detected')
elif varnish1 is not None:
    if varnish1.find('Cloudfront')!= -1:
        print ('Cloudfront WAF is detected')

if server is not None:
   if server=='PowerCDN':
       print ('Power CDN WAF is detected')
elif Powercdn is not None:
    print ('Power CDN WAF is detected')

if server is not None:
    if server=='Safedog WAF':
        print ('Safedog WAF is detected')
elif cookies is not None:
    if cookies.find('safedog-flow-item')!= -1:
        print ('Safedog WAF is detected')

if server is not None:
    if server=='XLabs WAF':
        print ('XLabs WAF is detected')
elif xlabs is not None:
    if xlabs.find('XLabs')!= -1:
        print ('XLabs WAF is detected')
