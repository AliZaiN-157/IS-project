import numpy as np
import re
import string
from urllib.parse import urlparse
from tldextract import extract as tld_extract
from tld import get_tld, is_tld
import ipaddress
import tldextract
import hashlib
import whois
from googlesearch import search
import warnings
warnings.filterwarnings("ignore")


def count_dot(url):
    """
    The URLs of phishing or malware websites frequently contain more than two subdomains. 
    A dot separates each domain (.). Every URL with more than three dot characters (.) raises 
    the risk of a malicious website
    """
    count_dot = url.count('.')
    return count_dot


def count_www(url):
    url.count('www')
    return url.count('www')


def count_at_symbols(url):
    return url.count('@')


def count_percentage(url):
    return url.count('%')


def count_https(url):
    return url.count('https')


def count_http(url):
    return url.count('http')


def count_qmarks(url):
    return url.count('?')


def count_hyphen(url):
    return url.count('-')


def count_equal(url):
    return url.count('=')


def secure_http(url):
    return int(urlparse(url).scheme == 'https')


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


def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0


def have_ip_address(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.hostname:
            ip = ipaddress.ip_address(parsed_url.hostname)
            return isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
    except ValueError:
        pass  # Invalid hostname or IP address

    return 0


def extract_primary_domain(url):
    try:
        res = get_tld(url, as_object=True,
                      fail_silently=False, fix_protocol=True)
        pri_domain = res.parsed_url.netloc
    except:
        pri_domain = None
    return pri_domain


def count_letters(url):
    num_letters = sum(char.isalpha() for char in url)
    return num_letters


def count_digits(url):
    num_digits = sum(char.isdigit() for char in url)
    return num_digits


def suspicious_words(url):
    match = re.search(
        'PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
    if match:
        return 1
    else:
        return 0


def google_index(url):
    site = search(url, 5)
    return 1 if site else 0


def count_special_chars(url):
    special_chars = set(string.punctuation)
    num_special_chars = sum(char in special_chars for char in url)
    return num_special_chars


def get_url_length(url):
    # Remove common prefixes
    prefixes = ['http://', 'https://']
    for prefix in prefixes:
        if url.startswith(prefix):
            url = url[len(prefix):]

    # Remove 'www.' if present
    url = url.replace('www.', '')

    # Return the length of the remaining URL
    return len(url)


tld_list = [
    '.tk', '.buzz', '.xyz', '.top', '.ga', '.ml', '.info', '.cf', '.gq', '.icu', '.wang', '.live', '.host', '.shop', '.top', '.icu', '.vip', '.id', '.cc', '.br', '.ci', '.zw', '.sx', '.mw'
]


def check_mal_tld(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc.lower()

    if any(netloc.endswith(tld) for tld in tld_list):
        return 1
    return 0


def abnormal_url(url):
    """
        check if a URL’s host or domain name (found in the netloc part of the URL) appears in the 
        full URL string. This can be used as a feature to detect possible phishing or malicious URLs, 
        where the structure of the URL might be suspicious.
    """
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc

    if netloc:
        netloc = str(netloc)
        match = re.search(netloc, url)

        if match:
            return 1
    return 0


def preprocess_url(url: str):

    status = []
    status.append(count_dot(url))
    status.append(check_mal_tld(url))
    status.append(google_index(url))
    status.append(suspicious_words(url))
    status.append(count_www(url))
    status.append(count_at_symbols(url))
    status.append(count_percentage(url))
    status.append(count_https(url))
    status.append(count_http(url))
    status.append(count_qmarks(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(secure_http(url))
    status.append(shortening_service(url))
    status.append(fd_length(url))
    status.append(have_ip_address(url))
    status.append(count_letters(url))
    status.append(count_digits(url))
    status.append(count_special_chars(url))
    status.append(get_url_length(url))
    status.append(abnormal_url(url))

    return status
