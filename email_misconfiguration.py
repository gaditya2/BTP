import dns.resolver #import the module
myResolver = dns.resolver.Resolver() #create a new instance named 'myResolver'
myAnswers = myResolver.query("iodigitalsec.com", "TXT") #Lookup the 'A' record(s) for google.com
for rdata in myAnswers: #for each response
    print (rdata) #print the data
    
name = rdata
print(type(name))
name = str(name)

name = name.split()
name = str(name)
if "spf1" in name:
        if "-" in name:
          print("YES")
        elif "~" in name:
          print("NO")
        elif "?" in name:
          print("NO")
else:
  print("NO")
