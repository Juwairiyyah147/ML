import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import itertools


import os
import seaborn as sns
import re
import regex    
from tldextract import extract
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime
import ssl
import socket
#importing the dataset
dataset = pd.read_csv("models/datasets/urlsdata.csv")
print(dataset.shape)
print(dataset.head())

print(dataset.type.value_counts())

import re
#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0
dataset['use_of_ip'] = dataset['url'].apply(lambda i: having_ip_address(i))

from urllib.parse import urlparse

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
       
        return 1
    else:
      
        return 0


dataset['abnormal_url'] = dataset['url'].apply(lambda i: abnormal_url(i))

from googlesearch import search

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0
dataset['google_index'] = dataset['url'].apply(lambda i: google_index(i))

def count_dot(url):
    count_dot = url.count('.')
    return count_dot

dataset['count.'] = dataset['url'].apply(lambda i: count_dot(i))
dataset.head()

def count_www(url):
    url.count('www')
    return url.count('www')

dataset['count-www'] = dataset['url'].apply(lambda i: count_www(i))

#The presence of the “@” symbol in the URL ignores everything previous to it.
def count_atrate(url):
     
    return url.count('@')

dataset['count@'] = dataset['url'].apply(lambda i: count_atrate(i))

#The presence of multiple directories in the URL generally indicates suspicious websites.
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

dataset['count_dir'] = dataset['url'].apply(lambda i: no_of_dir(i))

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

dataset['count_embed_domian'] = dataset['url'].apply(lambda i: no_of_embed(i))

#This feature is created to identify whether the URL uses URL shortening services like bit. \ly, goo.gl, go2l.ink, etc.
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0
    
    
dataset['short_url'] = dataset['url'].apply(lambda i: shortening_service(i))

# Generally malicious URLs do not use HTTPS protocols as it generally requires user credentials and ensures that the website is safe for transactions. 
def count_https(url):
    return url.count('https')


dataset['count-https'] = dataset['url'].apply(lambda i : count_https(i))

#Most of the time, phishing or malicious websites have more than one HTTP in their URL whereas safe sites have only one HTTP.
def count_http(url):
    return url.count('http')

dataset['count-http'] = dataset['url'].apply(lambda i : count_http(i))

#Safe sites generally contain less number of spaces whereas malicious websites generally contain more spaces in their URL hence more number of %.
def count_per(url):
    return url.count('%')

dataset['count%'] = dataset['url'].apply(lambda i : count_per(i))

# More number of ? in URL indicates suspicious URL.
def count_ques(url):
    return url.count('?')

dataset['count?'] = dataset['url'].apply(lambda i: count_ques(i))

#Phishers or cybercriminals generally add dashes(-) in prefix or suffix of the brand name so that it looks genuine URL
def count_hyphen(url):
    return url.count('-')


dataset['count-'] = dataset['url'].apply(lambda i: count_hyphen(i))


#Presence of equal to  is considered as riskier in URL as anyone can change the values to modify the page.
def count_equal(url):
    return url.count('=')

dataset['count='] = dataset['url'].apply(lambda i: count_equal(i))

#Average length of a safe URL is 74.
def url_length(url):
    return len(str(url))

dataset['url_length'] = dataset['url'].apply(lambda i: url_length(i))

#Hostname Length
def hostname_length(url):
    return len(urlparse(url).netloc)

dataset['hostname_length'] = dataset['url'].apply(lambda i: hostname_length(i))

dataset.head()
def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0
dataset['sus_url'] = dataset['url'].apply(lambda i: suspicious_words(i))


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


dataset['count-digits']= dataset['url'].apply(lambda i: digit_count(i))


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


dataset['count-letters']= dataset['url'].apply(lambda i: letter_count(i))


#Importing dependencies
from urllib.parse import urlparse
from tld import get_tld
import os.path

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

dataset['fd_length'] = dataset['url'].apply(lambda i: fd_length(i))

#Length of Top Level Domain
dataset['tld'] = dataset['url'].apply(lambda i: get_tld(i,fail_silently=True))


def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

dataset['tld_length'] = dataset['tld'].apply(lambda i: tld_length(i))





from sklearn.preprocessing import LabelEncoder

lb_make = LabelEncoder()
dataset["type_code"] = lb_make.fit_transform(dataset["type"])
dataset["type_code"].value_counts()

#plotting exploratory data analysis graph
import seaborn as sns
sns.set(style="darkgrid")
ax = sns.countplot(y="type", data=dataset,hue="use_of_ip")
