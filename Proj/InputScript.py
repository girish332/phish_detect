from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime
from googlesearch import search
import re

# -1 = OK
#  0 = Suspicious
#  1 = Phish

# all func name self explanatory else google

# function with #======.. above means copied whole or part of func
# area enclosed by 
        #====
#       .
        #====
#           means that part was copied. may or may not exist

def url_having_ip(url):
    having_ip=0
    symbol = re.findall(r'(http((s)?)://)((((\d)+).)*)((\w)+)(/((\w)+))?',url)
    if(len(symbol)!=0):
        having_ip = 1
    else:
        having_ip = -1 
    return(having_ip)
    return 0

def url_length(url):
    length=len(url)
    if(length<54):
        return -1
    elif(54<=length<=75):
        return 0
    else:
        return 1

def url_short(url):
    return 0

def having_at_symbol(url):
    symbol=re.findall(r'@',url)
    if(len(symbol)==0):
        return -1
    else:
        return 1 
    
def doubleSlash(url):
    return 0

def prefix_Suffix(url):
    SubDom, Dom, Suffix = extract(url)
    if(Dom.count('-')):
        return 1
    else:
        return -1

def sub_Dom(url):
    SubDom, Dom, Suffix = extract(url)
    if(SubDom.count('.')==0):
        return -1
    elif(SubDom.count('.')==1):
        return 0
    else:
        return 1

def SSLfinal_State(url):
    try:    
        if(re.search('https',url)):
            usehttps = 1
        else:
            usehttps = 0
#===============================================================================================================================================================================================================================================================================
        SubDom, Dom, Suffix = extract(url)
        host_name = Dom + "." + Suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0] 
            
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        

        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear-startingYear
#===============================================================================================================================================================================================================================================================================
        
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ):
            return -1 
        
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 0 
        else:
            return 1 
                
    except Exception as e:
        return 1

def Dom_registration(url):
    try:
        w = whois.whois(url)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp[0]-updated[0]).days
        if(length<=365):
            return 1
        else:
            return -1
    except:
        return 0

def favicon(url):
    return 0

def port(url):
    return 0

def https_token(url):
    SubDom, Dom, Suffix = extract(url)
    host =SubDom +'.' + Dom + '.' + Suffix 
    if(host.count('https')): 
        return 1
    else:
        return -1

def request_url(url):
    try:
        SubDom, Dom, Suffix = extract(url)
        websiteDom = Dom
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)
        
        linked_to_same = 0
        avg =0
        for image in imgs:
            SubDom, Dom, Suffix = extract(image['src'])
            imageDom = Dom
            if(websiteDom==imageDom or imageDom==''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)
        
        for video in vids:
            SubDom, Dom, Suffix = extract(video['src'])
            vidDom = Dom
            if(websiteDom==vidDom or vidDom==''):
                linked_to_same = linked_to_same + 1
                
        linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
            
        if(avg<0.22):
            return -1
        elif(0.22<=avg<=0.61):
            return 0
        else:
            return 1
    except:
        return 0


def url_of_anchor(url):
    try:
        SubDom, Dom, Suffix = extract(url)
        websiteDom = Dom
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            SubDom, Dom, Suffix = extract(anchor['href'])
            anchorDom = Dom
            if(websiteDom==anchorDom or anchorDom==''):
                linked_to_same = linked_to_same + 1
        linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
            
        if(avg<0.31):
            return -1
        elif(0.31<=avg<=0.67):
            return 0
        else:
            return 1
    except:
        return 0
    
    
def Links_in_tags(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        
        no_of_meta =0
        no_of_link =0
        no_of_script =0
        anchors=0
        avg =0
        
        for meta in soup.find_all('meta'):
            no_of_meta = no_of_meta+1
        for link in soup.find_all('link'):
            no_of_link = no_of_link +1
        for script in soup.find_all('script'):
            no_of_script = no_of_script+1
        for anchor in soup.find_all('a'):
            anchors = anchors+1
        
        total = no_of_meta + no_of_link + no_of_script+anchors
        tags = no_of_meta + no_of_link + no_of_script
        
        if(total!=0):
            avg = tags/total

        if(avg<0.17):
            return -1
        elif(0.17<=avg<=0.81):
            return 0
        else:
            return 1        
    except:        
        return 0


def sfh(url):
    return 0


def email_submit(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if(soup.find('mailto:')):
            return 1
        else:
            return -1 
    except:
        return 0


def abnormal_url(url):
    return 0

def redirect(url):
    return 0

def on_mouseover(url):
    return 0

def rightClick(url):
    return 0

def popup(url):
    return 0

def iframe(url):
    return 0

def age_of_Dom(url):
    try:
        Stats = whois.whois(url)
        start_date = Stats.creation_date
        current_date = datetime.datetime.now()
        age =(current_date-start_date[0]).days
        if(age>=180):
            return -1
        else:
            return 1
    except:
        return 0
        
def dns(url):
    return 0

def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
    except TypeError:
        return 1
    rank = int(rank)
    if (rank < 100000):
        return -1
    else:
        return 0

def page_rank(url):
    return 0

def google_index(url):
    try:
        site = search(url)
        return -1 if site else 1
    except:
        return 0

def links_pointing(url):
    return 0

def statistical(url):
    return 0

def main(url):  
    check = [[url_having_ip(url),
              url_length(url),
              url_short(url),
              having_at_symbol(url),
              doubleSlash(url),
              prefix_Suffix(url),
              sub_Dom(url),
              SSLfinal_State(url),
              Dom_registration(url),
              favicon(url),
              port(url),
              https_token(url),
              request_url(url),
              url_of_anchor(url),
              Links_in_tags(url),
              sfh(url),
              email_submit(url),
              abnormal_url(url),
              redirect(url),
              on_mouseover(url),
              rightClick(url),
              popup(url),
              iframe(url),
              age_of_Dom(url),
              dns(url),
              web_traffic(url),
              page_rank(url),
              google_index(url),
              links_pointing(url),
              statistical(url)]]

#    print(check)                uncomment to see O/P
    return check
   
  
  
  
