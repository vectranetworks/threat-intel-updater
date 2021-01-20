import json
import os
import sys
import logging.handlers
import time
from datetime import datetime, timedelta
try:
    import requests
    from requests import Request
    from indicators import IOC
except Exception as error:
    print('\nMissing import requirements: {}\n'.format(str(error)))
    sys.exit(0)

OAUTH_URL = "https://api.crowdstrike.com/oauth2/token"
BASE_URL = "https://api.crowdstrike.com/intel/combined/indicators/v1/"

LOG = logging.getLogger(__name__)


def gen_falcon_token(api_id, secret):
    """
    Generates API bearer token for Falcon's API which is good for 30 minutes

    :param api_id: API ID configured in Falcon
    :param secret: API secret configured in Falcon
    :return: bearer token string
    """
    oauth_payload = ("client_id=" + api_id + "&client_secret=" + secret)
    oauth_headers = {"accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(OAUTH_URL, headers=oauth_headers, data=oauth_payload)
    if resp.ok:
        return resp.json()['access_token']
    else:
        LOG.error('Exiting, unable to obtain bearer token: {}'.format(resp.json()['errors']))
        sys.exit(0)


def get_falcon_indicators(token, age=90, maximum=50000):
    """
    Returns Falcon indicators

    :param token: bearer-token
    :param age: indicates with age less than or equal to the number of specified days
    :param maximum: upper limit of the number of indicators returned total (max 50,000)
    :return: list of Falcon indicators
    """
    session = requests.Session()
    token_header = {"Authorization": "Bearer {}".format(token)}
    params = {
        'sort': '_marker.asc',
        'include_deleted': 'false',
        'limit': 10000,
        'offset': 0,
    }
    """
    Initialize total to 1, and ind_list = [] to start loop
    """
    total = 1
    ind_list = list()
    filters = ['type:"domain", type:"ip_address"']
    published = datetime.now() - timedelta(days=age)
    published_ts = int(published.timestamp())
    filters.append("published_date:>={}".format(published_ts))
    params['filter'] = '+'.join(filters)
    while params['offset'] <= (total or maximum):
        LOG.debug('Debug params{}'.format(params))

        indicators = Request('GET', BASE_URL, headers=token_header, params=params)
        prepared = indicators.prepare()
        resp = session.send(prepared)

        LOG.debug(resp.json()['meta'])
        LOG.debug('Falcon returned {} indicators this call.'.format(len(resp.json()['resources'])))

        if len(resp.json()['errors']) > 0:
            LOG.error('Falcon returned following error: {}'.format(resp.json()['errors']))

        if bool(resp.json()['meta'].get('pagination')):
            total = resp.json()['meta']['pagination']['total']

        params['offset'] += 10000
        ind_list += resp.json()['resources']
    return ind_list


def dump_indicators(indicators):
    """
    Debugging routine, not utilized in production
    """
    [print('indicator:{}, type:{}, labels-name:{}'.format(
        i['indicator'],
        i['type'],
        i['malware_families']
    )) for i in indicators]


def dump_iocs(iocs):
    """
    Debugging routine, not utilized in production
    """
    for n in iocs:
        print('{},{},{}'.format(n.value, n.type, n.label))


def gen_iocs(indicator_list):
    """
    Generates a list of IOCs from a list of Falcon indicators
    :param indicator_list: list of Falcon indicators, types ip_address or domain
    :return: list of IOC objects
    """
    ioc_list = list()
    [ioc_list.append(
        IOC(
            i['indicator'],
            'ip' if i['type'] == 'ip_address' else i['type'],
            i['malware_families']
        )) for i in indicator_list]
    return ioc_list


def main():
    log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    token = gen_falcon_token('5b20db43da5b429faac51a92733e7d66', 'l4WhedYNU8rfuLEGS910PZoQy2mbvtgI7niM35F6')
    indicators = get_falcon_indicators(token)
    LOG.info('Falcon returned {} total indicators'.format(len(indicators)))
    #  dump_indicators(indicators)
    falcon_iocs = gen_iocs(indicators)
    #  dump_iocs(falcon_iocs)


if __name__ == '__main__':
    main()
