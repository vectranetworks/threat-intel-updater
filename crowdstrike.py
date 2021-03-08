import sys
import logging.handlers
import logging
from systemd.journal import JournaldLogHandler
from datetime import datetime, timedelta
import itertools
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
journald_handler = JournaldLogHandler()
journald_handler.setFormatter(logging.Formatter(
    '[%(levelname)s] %(message)s'
))
LOG.addHandler(journald_handler)


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
    # filters = ['type:"domain", type:"ip_address"']
    filters = []
    published = datetime.now() - timedelta(days=kwargs['age'])
    published_ts = int(published.timestamp())

    if 'filter' in kwargs.keys():
        filters.append(kwargs['filter'])

    filters.append("published_date:>={}".format(published_ts))

    params['filter'] = '+'.join(filters)

    while params['offset'] <= total <= kwargs['max']:
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
            LOG.debug('Setting total to:{}'.format(total))
        params['offset'] += 10000
        ind_list += resp.json()['resources']
    return ind_list


def dump_indicators(indicators, raw_file):
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
    LOG.info('Dumping {} indicators to {}'.format(len(indicators), raw_file))
    with open(raw_file, 'w') as outfile:
        count = 0
        for i in indicators:
            count += 1
            for r in itertools.product(i['actors'], i['malware_families']):
                outfile.write('{},{},{},{},{},{},{}\n'.format(
                    i['indicator'],
                    i['type'],
                    r[0],
                    r[1],
                    i['malicious_confidence'],
                    i.get('targets'),
                    i.get('region')
                ))
                outfile.flush()
                print('{},{},{},{},{},{},{}\n'.format(
                    i['indicator'],
                    i['type'],
                    r[0],
                    r[1],
                    i['malicious_confidence'],
                    i.get('targets'),
                    i.get('region')
                ))
    LOG.info('Dumped {} indicators to file'.format(count))


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
            i['malware_families'] if len(i['malware_families']) > 0 else ['none'],
            i['actors'] if len(i['actors']) > 0 else ['none'],
            i['malicious_confidence'],
            None,
            i['targets'] if len(i['targets']) > 0 else ['none'],
            i.get('region') if bool(i.get('region')) and len(i.get('region')) > 0 else ['none']
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
    # indicators = get_falcon_indicators(token, kwargs['base_url'])
    indicators = get_falcon_indicators(token, **kwargs)
    LOG.debug('Falcon returned {} total indicators'.format(len(indicators)))

    falcon_iocs = gen_iocs(indicators)

    if bool(kwargs.get('raw_file')):
        dump_indicators_from_iocs(falcon_iocs, kwargs.get('raw_file'))

    # dump_iocs(falcon_iocs)
    return falcon_iocs


if __name__ == '__main__':
    get_crowdstrike()

