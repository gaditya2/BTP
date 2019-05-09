How to use security_header


python3 security_header.py --max-redirect 5 https://fb.com

output of this result is 

  Header 'x-frame-options' contains value 'DENY' ... [ OK ]
 Header 'strict-transport-security' contains value 'max-age=15552000; preload' ... [ OK ]
 Header 'access-control-allow-origin' is missing ... [ OK ]
 Header 'content-security-policy' is missing ... [ WARN ]
 Header 'x-xss-protection' contains value '0' ... [ WARN ]
 HTTPS supported ... [ OK ]
 HTTPS valid certificate ... [ OK ]
