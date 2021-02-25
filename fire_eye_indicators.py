import hashlib
import hmac
from urllib.parse import urlencode, quote_plus
import time
import json
import logging.handlers
import email
import itertools
import sys
try:
    import requests
    from requests import Request
    import indicators
except Exception as error:
    print('\nMissing import requirements: {}\n'.format(str(error)))
    sys.exit(0)


class Error(Exception):
    pass


class InvalidConfigError(Error):
    def __init__(self, message):
        self.message = message


LOG = logging.getLogger(__name__)


def validate_config(func):
    def check_config(**kwargs):
        if all(value is not '' for value in kwargs.values()):
            return func(**kwargs)
        else:
            LOG.info('Configuration not valid skipping. {}'.format(kwargs))
            raise InvalidConfigError("Invalid FireEye configuration.")
    return check_config


def get_fireeye_indicators(**kwargs):

    ind_list = list()
    public_key = kwargs['api_id']
    private_key = kwargs['secret']

    url = kwargs['base_url']
    search_uri = kwargs['filter']

    '''Setup time related values'''
    time_val = kwargs['age'] * 86400
    dates = {
        'startDate': int(time.time()) - time_val,
        'endDate': int(time.time())
    }
    # time_stamp utilized in authentication
    date_time = email.utils.formatdate(localtime=True)
    # Mon, 22 Feb 2021 15:51:59 -0600
    # print('Time Stamp:{}'.format(date_time))

    query = urlencode(dates, quote_via=quote_plus)
    # print(query)

    uri = '/view/iocs?' + str(query) + '&format=json' + search_uri
    accept_header = 'application/json'
    api_version = '2.6'

    auth_data = uri + api_version + accept_header + date_time

    hashed = hmac.new(private_key.encode('utf-8'), auth_data.encode('utf-8'), hashlib.sha256)

    headers = {
        'Accept': accept_header,
        'Accept-Version': api_version,
        'X-Auth': public_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Date': date_time,
        'Content-Type': accept_header,
        'X-App-Name': kwargs['X-App-Name']
    }
    response = requests.get(url + uri, headers=headers, verify=False)
    
    if response.status_code == 200:
        parsed = json.loads(response.text)
        ind_list = parsed[u'message']
        LOG.debug(json.dumps(ind_list, indent=4))
        return ind_list

    if response.status_code != 200:
        LOG.error('Fire Eye Error Response:{}'.format(response.content))
        LOG.error('Status code:{}'.format(response.status_code))
        LOG.error('Reason:{}'.format(response.reason))
        return ind_list


def gen_iocs(indicator_list):
    """
    Generates a list of IOCs from a list of FireEye indicators
    :param indicator_list: list of FireEye indicators, types ip_address or domain
    :return: list of IOC objects
    """
    ioc_list = list()
    for i in indicator_list:
        if i.get('ip') is not None:
            ioc_list.append(
                indicators.IOC(
                    i['ip'],
                    'ip',
                    [i.get('intelligenceType')],
                    None,
                    None,
                    i.get('title')
                )
            )
        elif i.get('domain') is not None:
            ioc_list.append(
                indicators.IOC(
                    i['domain'],
                    'domain',
                    [i.get('intelligenceType')],
                    None,
                    None,
                    i.get('title')
                )
            )
    return ioc_list


def dump_indicators(indicators, raw_file):
    return


def dump_indicators_from_iocs(iocs, raw_file):
    """
    Optional output of raw indicators to csv file
    """
    """
    with open(raw_file, 'w') as outfile:
        [outfile.write('{},{},{},{},{}\n'.format(
            i['indicator'],
            i['type'],
            i['actors'],
            i['malware_families'],
            i['malicious_confidence']
        )) for i in indicators]
    """
    LOG.info('Dumping {} indicators to {}'.format(len(iocs), raw_file))
    with open(raw_file, 'w') as outfile:
        count = 0
        for i in iocs:
            count += 1
            for r in itertools.product(i.label, i.actor, i.industry, i.region):
                outfile.write('{},{},{},{},{},{},{},{}\n'.format(
                    i.value,
                    i.type,
                    r[0],
                    r[1],
                    i.confidence,
                    i.description,
                    r[2],
                    r[3]
                ))
    LOG.info('Dumped {} indicators to file'.format(count))


def dump_iocs(iocs):
    """
    Debugging routine, not utilized in production
    """
    for n in iocs:
        print('{},{},{},{},{},{},{},{}'.format(
            n.value, n.type, n.label, n.actor, n.confidence, n.description, n.industry, n.region
        ))


@validate_config
def get_fireeye(**kwargs):
    """
    Generates list of FireEye indicators

    :param kwargs: api_id, api secret, base_url (configured in config.json)
    :return: list of IOC class IOCs
    """

    indicators = get_fireeye_indicators(**kwargs)
    LOG.info('FireEye returned {} total indicators'.format(len(indicators)))

    fireeye_iocs = gen_iocs(indicators)

    if bool(kwargs.get('raw_file')):
        dump_indicators_from_iocs(fireeye_iocs, kwargs.get('raw_file'))

    # dump_iocs(fireeye_iocs)

    return fireeye_iocs


if __name__ == '__main__':
    get_fireeye()
