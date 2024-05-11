# -*- coding: utf-8 -*-

#importing libraries
import joblib
#import inputScript
from featureeng import *
#load the pickle file
classifier = joblib.load('final_models/rf_final.pkl')
import numpy as np
import re
import regex    
from tldextract import extract
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime


def main(url):
    
    status = []
    
    status.append(having_ip_address(url))
    status.append(url_length(url))
    status.append(shortening_service(url))
    status.append(count_atrate(url))
    status.append(no_of_embed(url))
    status.append(prefix_suffix(url))
    status.append(sub_domain(url))
    status.append(https_token(url))

    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    
    status.append(no_of_dir(url))
    
    
    
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
   
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)
    status.append(tld_length(tld))

    

    return status 

def get_prediction_from_url(test_url):
    features_test = main(test_url)
    #  2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))
    print(features_test)
    

    pred = classifier.predict(features_test)
    if int(pred[0]) == 0:
        
        res="SAFE"
        return res
    elif int(pred[0])==1:        
        res="UNSAFE ! No virus threat "
        return res
    elif int(pred[0])==2:        
        res="UNSAFE ! No virus threat but sensitive data can be stolen "
        return res
    elif int(pred[0])==3:      
        res="UNSAFE ! Virus Threat! "
        return res
    else:
        res="UNSAFE "
        return res

urls = ['titaniumcorporate.co.za','www.kaggle.com', 'br-icloud.com.br','http://www.ikenmijnkunst.nl/index.php/exposities/exposities-2006','www.facebook.com']
for url in urls:
     print(get_prediction_from_url(url))
#checking and predicting
#checkprediction = inputScript.main(url)
#prediction = classifier.predict(checkprediction)

# print(prediction)

# x = prediction.tolist()
#print(type(prediction))


