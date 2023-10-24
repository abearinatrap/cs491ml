# grab data about url from sites
# copied from https://data.mendeley.com/datasets/c2gw7fy2j4/3/files/562f107e-e96e-47f9-8635-a326b1d5fae4


from datetime import datetime
from bs4 import BeautifulSoup
import requests
import whois
import time
import re


#################################################################################################################################
#               Domain registration age 
#################################################################################################################################

def domain_registration_length(domain):
    try:
        res = whois.whois(domain)
        expiration_date = res.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        # Some domains do not have expiration dates. The application should not raise an error if this is the case.
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return -1

def domain_registration_length1(domain):
    v1 = -1
    v2 = -1
    try:
        host = whois.whois(domain)
        hostname = host.domain_name
        expiration_date = host.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    v1 = 0
            v1= 1
        else:
            if re.search(hostname.lower(), domain):
                v1 = 0
            else:
                v1= 1  
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            v2= 0
    except:
        v1 = 1
        v2 = -1
        return v1, v2
    return v1, v2

#################################################################################################################################
#               Domain recognized by WHOIS
#################################################################################################################################

 
def whois_registered_domain(domain):
    try:
        hostname = whois.whois(domain).domain_name
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    return 0
            return 1
        else:
            if re.search(hostname.lower(), domain):
                return 0
            else:
                return 1     
    except:
        return 1

#################################################################################################################################
#               Unable to get web traffic (Page Rank)
#################################################################################################################################
import urllib

def web_traffic(short_url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + short_url).read(), "xml").find("REACH")['RANK']
        except:
            return 0
        return int(rank)


#################################################################################################################################
#               Domain age of a url
#################################################################################################################################

import json

def domain_age(domain):

    url = domain.split("//")[-1].split("/")[0].split('?')[0]
    show = "https://input.payapi.io/v1/api/fraud/domain/age/" + url
    r = requests.get(show)

    if r.status_code == 200:
        data = r.text
        jsonToPython = json.loads(data)
        result = jsonToPython['result']
        if result == None:
            return -2
        else:
            return result
    else:       
        return -1


#################################################################################################################################
#               Global rank
#################################################################################################################################

def global_rank(domain):
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": domain
    })
    
    try:
        return int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        return -1


#################################################################################################################################
#               Google index
#################################################################################################################################


from urllib.parse import urlencode

def google_index(url):
    #time.sleep(.6)
    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        #print(check)
        if check and check['href']:
            return 0
        else:
            return 1
        
    except AttributeError:
        return 1

#print(google_index('http://www.google.com'))
#################################################################################################################################
#               DNSRecord  expiration length
#################################################################################################################################

import dns.resolver

def dns_record(domain):
    try:
        nameservers = dns.resolver.query(domain,'NS')
        if len(nameservers)>0:
            return 0
        else:
            return 1
    except:
        return 1

#################################################################################################################################
#               Page Rank from OPR
#################################################################################################################################


def page_rank(key, domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(url, headers={'API-OPR':key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1
    
# copied from https://data.mendeley.com/datasets/c2gw7fy2j4/3/files/2cb9aa39-5aa5-4c84-a455-a8dbcc03526e

# 0 stands for legitimate
# 1 stands for phishing

import re


#LOCALHOST_PATH = "/var/www/html/"
HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

allbrand_txt = open("data/allbrands.txt", "r")

def __txt_to_list(txt_object):
    list = []
    for line in txt_object:
        list.append(line.strip())
    txt_object.close()
    return list

allbrand = __txt_to_list(allbrand_txt)
#print(allbrand)

#################################################################################################################################
#               Having IP address in hostname
#################################################################################################################################

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

#################################################################################################################################
#               URL hostname length 
#################################################################################################################################

def url_length(url):
    return len(url) 


#################################################################################################################################
#               URL shortening
#################################################################################################################################

def shortening_service(full_url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      full_url)
    if match:
        return 1
    else:
        return 0


#################################################################################################################################
#               Count at (@) symbol at base url
#################################################################################################################################

def count_at(base_url):
     return base_url.count('@')
 
#################################################################################################################################
#               Count comma (,) symbol at base url
#################################################################################################################################

def count_comma(base_url):
     return base_url.count(',')

#################################################################################################################################
#               Count dollar ($) symbol at base url
#################################################################################################################################

def count_dollar(base_url):
     return base_url.count('$')

#################################################################################################################################
#               Having semicolumn (;) symbol at base url
#################################################################################################################################

def count_semicolumn(url):
     return url.count(';')

#################################################################################################################################
#               Count (space, %20) symbol at base url (Das'19)
#################################################################################################################################

def count_space(base_url):
     return base_url.count(' ')+base_url.count('%20')

#################################################################################################################################
#               Count and (&) symbol at base url (Das'19)
#################################################################################################################################

def count_and(base_url):
     return base_url.count('&')


#################################################################################################################################
#               Count redirection (//) symbol at full url
#################################################################################################################################

def count_double_slash(full_url):
    list=[x.start(0) for x in re.finditer('//', full_url)]
    if list[len(list)-1]>6:
        return 1
    else:
        return 0
    return full_url.count('//')


#################################################################################################################################
#               Count slash (/) symbol at full url
#################################################################################################################################

def count_slash(full_url):
    return full_url.count('/')

#################################################################################################################################
#               Count equal (=) symbol at base url
#################################################################################################################################

def count_equal(base_url):
    return base_url.count('=')

#################################################################################################################################
#               Count percentage (%) symbol at base url (Chiew2019)
#################################################################################################################################

def count_percentage(base_url):
    return base_url.count('%')


#################################################################################################################################
#               Count exclamation (?) symbol at base url
#################################################################################################################################

def count_exclamation(base_url):
    return base_url.count('?')

#################################################################################################################################
#               Count underscore (_) symbol at base url
#################################################################################################################################

def count_underscore(base_url):
    return base_url.count('_')


#################################################################################################################################
#               Count dash (-) symbol at base url
#################################################################################################################################

def count_hyphens(base_url):
    return base_url.count('-')

#################################################################################################################################
#              Count number of dots in hostname
#################################################################################################################################

def count_dots(hostname):
    return hostname.count('.')

#################################################################################################################################
#              Count number of colon (:) symbol
#################################################################################################################################

def count_colon(url):
    return url.count(':')

#################################################################################################################################
#               Count number of stars (*) symbol (Srinivasa Rao'19)
#################################################################################################################################

def count_star(url):
    return url.count('*')

#################################################################################################################################
#               Count number of OR (|) symbol (Srinivasa Rao'19)
#################################################################################################################################

def count_or(url):
    return url.count('|')


#################################################################################################################################
#               Path entension != .txt
#################################################################################################################################

def path_extension(url_path):
    if url_path.endswith('.txt'):
        return 1
    return 0

#################################################################################################################################
#               Having multiple http or https in url path
#################################################################################################################################

def count_http_token(url_path):
    return url_path.count('http')

#################################################################################################################################
#               Uses https protocol
#################################################################################################################################

def https_token(scheme):
    if scheme == 'https':
        return 0
    return 1

#################################################################################################################################
#               Ratio of digits in hostname 
#################################################################################################################################

def ratio_digits(hostname):
    return len(re.sub("[^0-9]", "", hostname))/len(hostname)

#################################################################################################################################
#               Count number of digits in domain/subdomain/path
#################################################################################################################################

def count_digits(line):
    return len(re.sub("[^0-9]", "", line))

#################################################################################################################################
#              Checks if tilde symbol exist in webpage URL (Chiew2019)
#################################################################################################################################

def count_tilde(full_url):
    if full_url.count('~')>0:
        return 1
    return 0


#################################################################################################################################
#               number of phish-hints in url path 
#################################################################################################################################

def phish_hints(url_path):
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count

#################################################################################################################################
#               Check if TLD exists in the path 
#################################################################################################################################

def tld_in_path(tld, path):
    if path.lower().count(tld)>0:
        return 1
    return 0
    
#################################################################################################################################
#               Check if tld is used in the subdomain 
#################################################################################################################################

def tld_in_subdomain(tld, subdomain):
    if subdomain.count(tld)>0:
        return 1
    return 0

#################################################################################################################################
#               Check if TLD in bad position (Chiew2019)
#################################################################################################################################

def tld_in_bad_position(tld, subdomain, path):
    if tld_in_path(tld, path)== 1 or tld_in_subdomain(tld, subdomain)==1:
        return 1
    return 0



#################################################################################################################################
#               Abnormal subdomain starting with wwww-, wwNN
#################################################################################################################################

def abnormal_subdomain(url):
    if re.search('(http[s]?://(w[w]?|\d))([w]?(\d|-))',url):
        return 1
    return 0
    

#################################################################################################################################
#               Number of redirection 
#################################################################################################################################

def count_redirection(page):
    return len(page.history)
    
#################################################################################################################################
#               Number of redirection to different domains
#################################################################################################################################

def count_external_redirection(page, domain):
    count = 0
    if len(page.history) == 0:
        return 0
    else:
        for i, response in enumerate(page.history,1):
            if domain.lower() not in response.url.lower():
                count+=1          
            return count

    
#################################################################################################################################
#               Is the registered domain created with random characters (Sahingoz2019)
#################################################################################################################################

# from word_with_nlp import nlp_class

# def random_domain(domain):
#         nlp_manager = nlp_class()
#         return nlp_manager.check_word_random(domain)
    
#################################################################################################################################
#               Consecutive Character Repeat (Sahingoz2019)
#################################################################################################################################

def char_repeat(words_raw):
    
        def __all_same(items):
            return all(x == items[0] for x in items)

        repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
        part = [2, 3, 4, 5]

        for word in words_raw:
            for char_repeat_count in part:
                for i in range(len(word) - char_repeat_count + 1):
                    sub_word = word[i:i + char_repeat_count]
                    if __all_same(sub_word):
                        repeat[str(char_repeat_count)] = repeat[str(char_repeat_count)] + 1
        return  sum(list(repeat.values()))
    
#################################################################################################################################
#               puny code in domain (Sahingoz2019)
#################################################################################################################################

def punycode(url):
    if url.startswith("http://xn--") or url.startswith("http://xn--"):
        return 1
    else:
        return 0

#################################################################################################################################
#               domain in brand list (Sahingoz2019)
#################################################################################################################################

def domain_in_brand(domain):
        
    if domain in allbrand:
        return 1
    else:
        return 0
 
import Levenshtein
def domain_in_brand1(domain):
    for d in allbrand:
        if len(Levenshtein.editops(domain.lower(), d.lower()))<2:
            return 1
    return 0



#################################################################################################################################
#               brand name in path (Srinivasa-Rao2019)
#################################################################################################################################

def brand_in_path(domain,path):
    for b in allbrand:
        if '.'+b+'.' in path and b not in domain:
           return 1
    return 0


#################################################################################################################################
#               count www in url words (Sahingoz2019)
#################################################################################################################################

def check_www(words_raw):
        count = 0
        for word in words_raw:
            if not word.find('www') == -1:
                count += 1
        return count
    
#################################################################################################################################
#               count com in url words (Sahingoz2019)
#################################################################################################################################

def check_com(words_raw):
        count = 0
        for word in words_raw:
            if not word.find('com') == -1:
                count += 1
        return count

#################################################################################################################################
#               check port presence in domain
#################################################################################################################################

def port(url):
    if re.search("^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):([0-9]+)",url):
        return 1
    return 0

#################################################################################################################################
#               length of raw word list (Sahingoz2019)
#################################################################################################################################

def length_word_raw(words_raw):
    return len(words_raw) 

#################################################################################################################################
#               count average word length in raw word list (Sahingoz2019)
#################################################################################################################################

def average_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return sum(len(word) for word in words_raw) / len(words_raw)

#################################################################################################################################
#               longest word length in raw word list (Sahingoz2019)
#################################################################################################################################

def longest_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return max(len(word) for word in words_raw) 

#################################################################################################################################
#               shortest word length in raw word list (Sahingoz2019)
#################################################################################################################################

def shortest_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return min(len(word) for word in words_raw) 


#################################################################################################################################
#               prefix suffix
#################################################################################################################################

def prefix_suffix(url):
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        return 1
    else:
        return 0 

#################################################################################################################################
#               count subdomain
#################################################################################################################################

def count_subdomain(url):
    if len(re.findall("\.", url)) == 1:
        return 1
    elif len(re.findall("\.", url)) == 2:
        return 2
    else:
        return 3

#################################################################################################################################
#               Suspecious TLD
#################################################################################################################################

suspecious_tlds = ['fit','tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click', # Spamhaus
        'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
        'ren', 'mom', 'party', 'review', 'trade', 'accountants', 
        'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
        'accountant', 'realtor', 'top', 'christmas', 'gdn', # Shady Top-Level Domains
        'link', # Blue Coat Systems
        'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
        'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au' # statistics
        ]


def suspecious_tld(tld):
   if tld in suspecious_tlds:
       return 1
   return 0