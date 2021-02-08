import hashlib
import hmac
import json
import email
import urllib
import urllib3
import time
import sys
import requests
import os
import re
import glob
import logging.handlers

# ***************** DONT FORGET THIS ********************
urllib3.disable_warnings()

LOG = logging.getLogger(__name__)

# SET AMOUNT OF DAYS OF REPORTS TO RETRIEVE <=90
# days = 30

# SET DIRECTORY FOR DOWNLOADED STIX.XML FILES
# LOCAL TO PYTHON SCRIPT
# directory = "stix-files"

# SET API KEYS HERE
# public_key = ''
# private_key = ''

# SET PROXY INFORMATION (IP, PORT, AD USERNAME)
PROXY_HOST = ''
PROXY_PORT = ''
PROXY_USER = ''
PROXY_PASS = ''

proxies = {
    'http': 'http://' + PROXY_USER + ':' + PROXY_PASS + '@' + PROXY_HOST + ':' + str(PROXY_PORT),
    'https': 'https://' + PROXY_USER + ':' + PROXY_PASS + '@' + PROXY_HOST + ':' + str(PROXY_PORT)
}

# SET THREATSCAPES TO RETRIEVE
# threatscapes = '&threatScape=cyberEspionage,hacktivism,enterprise,cyberCrime,criticalInfrastructure,vulnerabilityAndExploitation'
audience = '&audience=fusion'

url = 'https://api.isightpartners.com'


# STIX QUERY CODE
def get_stix_report(report, title, public_key, private_key, stix_dir):
    time_stamp = email.utils.formatdate(localtime=True)
    search_query = '/report/' + report + '?format=stix&detail=full&iocsOnly=True'
    accept_version = '2.6'
    accept_header = 'application/stix'
    new_data = search_query + accept_version + accept_header + time_stamp
    key = bytearray()
    key.extend(map(ord, private_key))
    hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)
    headers = {
        'Accept': accept_header,
        'Accept-Version': accept_version,
        'X-Auth': public_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Date': time_stamp,
        'Content-Type': accept_header,
        'X-App-Name': 'Vectra-AI-V0.5.py'
    }
    r = requests.get(url + search_query, headers=headers, verify=False)
    response = r.content.decode('utf-8')
    if re.findall(r'Observable', response):
        try:
            with open(stix_dir + "/" + report + '.xml', 'w', encoding='utf-8') as f:
                LOG.info('Written: {} \t {}'.format(str(report), str(title)))
                f.write(response)
                f.close()
        except ValueError:
            print("Value Error: " + str(report) + str(title))
            print(response)
        except:
            import traceback
            traceback.print_exc()
    return ()


# JSON /report/index code
def get_report_index(public_key, private_key, stix_dir, days):
    # THIS IS NOT THE CODE YOU'RE LOOKING FOR
    timeVal = days * 86400
    dtg = {
        'startDate': int(time.time()) - timeVal,
        'endDate': int(time.time())
    }
    enc_q = '/report/index?' + urllib.parse.urlencode(dtg) + audience
    time_stamp = email.utils.formatdate(localtime=True)
    accept_version = '2.6'
    accept_header = 'application/json'
    query = enc_q + accept_version + accept_header + time_stamp
    key = bytearray()
    key.extend(map(ord, private_key))
    hashed = hmac.new(key, query.encode('utf-8'), hashlib.sha256)
    headers = {
        'Accept': accept_header,
        'Accept-Version': accept_version,
        'X-Auth': public_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Date': time_stamp,
        'Content-Type': accept_header,
        'X-App-Name': 'Vectra-AI-V0.5.py'
    }

    # Get the initial data
    r = requests.get(url + enc_q, headers=headers, verify=False)
    parsed = json.loads(r.text)
    if r.status_code != 200:
        sys.exit('\nAPI Error: {}'.format(r.text))
    content = parsed[u'message']
    reports = []
    LOG.info("Generating Reports : ")
    for rID in content:
        get_stix_report(rID['reportId'], rID['title'], public_key, private_key, stix_dir)
    return ()


def purge_files(glb):
    LOG.info('Purging old STIX files.')
    list(map(os.remove, glob.glob(glb)))


def fireeye(**kwargs):
    directory = kwargs.get('stix_dir')
    if not os.path.exists(directory):
        os.makedirs(directory)

    purge_files(kwargs.get('stix_dir') + '*.xml')
    get_report_index(kwargs.get('api_id'), kwargs.get('secret'), directory, kwargs.get('age'))


if __name__ == '__main__':
    fireeye()
