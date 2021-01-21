import sys
import logging.handlers
from datetime import datetime, timedelta
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


OAUTH_URL = "https://api.crowdstrike.com/oauth2/token"

LOG = logging.getLogger(__name__)


def validate_config(func):
    def check_config(**kwargs):
        if all(value is not '' for value in kwargs.values()):
            return func(**kwargs)
        else:
            LOG.info('Configuration not valid skipping. {}'.format(kwargs))
            raise InvalidConfigError("Invalid Crowdstrike configuration.")
    return check_config


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


def get_falcon_indicators(access_token, **kwargs):
    """
    Returns Falcon indicators

    :param access_token: bearer-token
    :param base_url: url for the correct falcon region
    :param age: indicates with age less than or equal to the number of specified days
    :param max: upper limit of the number of indicators returned total (max 50,000)
    :return: list of Falcon indicators
    """
    session = requests.Session()
    token_header = {"Authorization": "Bearer {}".format(access_token)}
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
    published = datetime.now() - timedelta(days=kwargs['age'])
    published_ts = int(published.timestamp())

    if 'filter' in kwargs.keys():
        filters.append(kwargs['filter'])

    filters.append("published_date:>={}".format(published_ts))

    params['filter'] = '+'.join(filters)

    while params['offset'] <= (total and kwargs['max']):
        params['limit'] = kwargs['max'] - params['offset'] if \
            kwargs['max'] - params['offset'] < params['limit'] else params['limit']

        LOG.debug('Debug params{}'.format(params))

        indicators = Request('GET', kwargs['base_url'], headers=token_header, params=params)
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
        indicators.IOC(
            i['indicator'],
            'ip' if i['type'] == 'ip_address' else i['type'],
            i['malware_families'],
            i['malicious_confidence']
        )) for i in indicator_list]
    return ioc_list


@validate_config
def get_crowdstrike(**kwargs):
    """
    Generates list of Crowdstrike Falcon indicators

    :param kwargs: api_id, api secret, base_url (configured in config.json)
    :return: list of IOC class IOCs
    """
    token = gen_falcon_token(kwargs['api_id'], kwargs['secret'])
    #indicators = get_falcon_indicators(token, kwargs['base_url'])
    indicators = get_falcon_indicators(token, **kwargs)
    LOG.debug('Falcon returned {} total indicators'.format(len(indicators)))
    #  dump_indicators(indicators)
    falcon_iocs = gen_iocs(indicators)
    #  dump_iocs(falcon_iocs)
    return falcon_iocs


if __name__ == '__main__':
    get_crowdstrike()
