import re
import logging
import sys
# import logging.handlers
# import json

try:
    from taxii2client.v20 import Server
    from taxii2client.v20 import Collection, as_pages
    import indicators
except Exception as error:
    print('\nMissing import requirements: {}\n'.format(str(error)))
    sys.exit(0)

LOG = logging.getLogger(__name__)


class Error(Exception):
    pass


class InvalidConfigError(Error):
    def __init__(self, message):
        self.message = message


def validate_config(func):
    def check_config(**kwargs):
        if all(value is not '' for value in kwargs.values()):
            return func(**kwargs)
        else:
            LOG.info('Configuration not valid skipping. {}'.format(kwargs))
            raise InvalidConfigError("Invalid Anomali configuration.")
    return check_config


def get_collections(server):
    """
    Obtains a list of Anomali collections from the specified server
    :param server: anomali server object
    :return: dictionary of collections {title: url}
    """
    collection_dict = dict()
    for col in server.default.collections:
        collection_dict[col.title] = col.url
    return collection_dict


def get_collection(col_url, **kwargs):
    """
    Obtains all objects from the provided a collection url
    :param col_url: url of collection
    :param kwargs: anomali config
    :return: list of anomali objects
    """
    collection = Collection(col_url, user=kwargs.get('user'), password=kwargs.get('password'))
    collection_dict = collection.get_objects()
    return collection_dict.get('objects')


def process_pattern(pattern):
    """
    Extracts IOC from provided pattern
    :param pattern: anomali string
    :return: IOC
    """
    indicator = dict()
    LOG.debug('Pattern [ {} ]'.format(pattern))
    if pattern is not None:
        i = pattern.split(' = ')
        url_result = re.search('url:value', i[0])
        ip_result = re.search('ipv4-addr:value', i[0])
        domain_result = re.search('domain-name:value', i[0])
        if bool(ip_result):
            ip = re.search('([^\'][\d\.]+)', i[1])
            if bool(ip):
                indicator['ip'] = ip.group(0)
                LOG.debug('Found indicator IP: {}'.format(indicator))
                return indicator
            else:
                LOG.info('IP parse error:{}'.format(i[1]))
                return None

        elif bool(url_result):
            url = re.search('([^\'][\w:/\.\-]+)', i[1])
            if bool(url):
                indicator['url'] = url.group(0)
                LOG.debug('Found indicator URL: {}'.format(indicator))
                return indicator
            else:
                LOG.info('URL parse error:{}'.format(i[1]))
                return None
        elif bool(domain_result):
            domain = re.search('[^\'][\w/\.\-]+', i[1])
            if bool(domain):
                indicator['domain'] = domain.group(0)
                LOG.debug('Found indicator Domain: {}'.format(indicator))
                return indicator
            else:
                LOG.info('Domain parse error:{}'.format(i[1]))
                return None
        else:
            LOG.info('Undefined type:{}'.foramt(pattern))
            return None
    else:
        return None


def process_severity(labels):
    """
    Extracts appropriate certainty from anomaly label
    :param labels: anomaly label
    :return: Low, Medium, or High
    """
    i = [i for i, elem in enumerate(labels) if 'confidence' in elem]
    try:
        match = re.search('[^\-][\d]+', labels[i[0]])
        cert = int(match.group(0))
        if cert in range(0, 34):
            return 'Low'
        elif cert in range(33, 67):
            return 'Medium'
        elif cert in range(66, 101):
            return 'High'
        else:
            return None
    except:
        return None


def gen_iocs(indicator_list):
    """
    Generates a list of IOCs from a list of Anomali indicators
    :param indicator_list: list of Anomali indicators, types ip_address, url, or domain
    :return: list of IOC objects
    """
    ioc_list = list()
    for i in indicator_list:
        pp = process_pattern(i.get('pattern'))
        if pp:
            t, v = pp.popitem()
        else:
            t, v = None, None
        if t and v is not None:
            ioc_list.append(
                indicators.IOC(
                    v,
                    t,
                    [i.get('labels')],
                    None,
                    process_severity(i.get('labels')),
                    i.get('description'),
                    None,
                    None
                )
            )
    return ioc_list


def dump_iocs(iocs):
    """
    Debugging routine, not utilized in production
    """
    for n in iocs:
        print('{},{},{},{},{},{},{},{}'.format(
            n.value, n.type, n.label, n.actor, n.confidence, n.description, n.industry, n.region
        ))


@validate_config
def get_anomali(**kwargs):
    """
    Generates a list of Anomali indicators per collection.

    :param kwargs: anomali_server, collection_list
    :return: A list of dictionaries [{collection_name: ioc_list}, {collection_name: ioc_list}]
    """

    LOG.debug('Collecting Anomali Collections.')
    anomali_server = Server(kwargs.get('base_url'), user=kwargs.get('user'), password=kwargs.get('password'))
    collections_dict = get_collections(anomali_server)
    anomali_dict_list = list()
    if len(collections_dict) > 0:
        LOG.info('Obtained [ {} ] Collections from Anomali, attempting to process [ {} ] Collections per config.'
                 .format(len(collections_dict), len(list(kwargs.get('collection_list')))))
        for col_name in kwargs.get('collection_list'):
            LOG.info('Attempting to get Anomali collection [ {} ], [ {} ]'
                     .format(col_name, collections_dict.get(col_name)))
            indicator_list = get_collection(collections_dict.get(col_name), **kwargs)
            if len(indicator_list) > 0:
                LOG.info('Attempting to generate [ {} ] IOCs.'.format(len(indicator_list)))
                anomali_iocs = gen_iocs(indicator_list)
                anomali_dict_list.append({col_name.replace(' ', ''): anomali_iocs})
                # LOG.info('Dumping [ ] IOCs.'.format(len(iocs)))
                # dump_iocs(iocs)
    return anomali_dict_list


if __name__ == '__main__':
    get_anomali()

