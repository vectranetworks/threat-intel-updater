import logging.handlers
import json
import time
import ssl
"""Commented out until all stix modules are determined"""
#  try:
import crowdstrike
import vat.vectra as vectra
import requests
from stix.core import STIXPackage
from stix.indicator import Indicator, CompositeIndicatorExpression
from stix.ttp import TTP, Resource, Behavior
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.infrastructure import Infrastructure
from stix.ttp.behavior import Behavior
from stix.common.related import RelatedTTP
from cybox.core import Observable, ObservableComposition
from cybox.objects.address_object import Address
from stix.campaign import Campaign
from stix.common.vocabs import VocabString
from stix.threat_actor import ThreatActor
from cybox.objects.email_message_object import EmailMessage, Attachments, AttachmentReference
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.mutex_object import Mutex
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.network_connection_object import NetworkConnection
from stix.common import Identity
"""
except Exception as error:
    print('\nMissing import requirements: {}\n'.format(str(error)))
    sys.exit(0)
"""

LOG = logging.getLogger(__name__)

"""Suppress Detect certificate warning"""
requests.packages.urllib3.disable_warnings()
ssl._create_default_https_context = ssl._create_unverified_context


class IOC:
    """
    Class to create an IOC object
    """
    def __init__(self, ioc=None, ioc_type=None, ioc_label=None, ioc_confidence=None):
        self.value = ioc if ioc is not None else []
        self.type = ioc_type if (ioc_type in ['ip', 'domain']) else 'undef'
        self.label = ioc_label if ioc_label is not None else []
        self.confidence = ioc_confidence if ioc_confidence is not None else None


def validate_cognito_config(func):
    def check_cognito_config(**kwargs):
        if all(value is not '' for value in kwargs.values()):
            return func(**kwargs)
        else:
            raise Exception('Ensure config.json has valid cognito configuration.')
    return check_cognito_config


def package_ioc(pkg, ioc):
    indicator = Indicator()
    if ioc.type == 'ip':
        address = Address()
        address.address_value = ioc.value
        address.address_value.condition = "Equals"
        indicator.observable = Observable(address)
        indicator.confidence = ioc.confidence
    elif ioc.type == 'domain':
        domain = DomainName()
        domain.value = ioc.value
        indicator.observable = Observable(domain)
        indicator.confidence = ioc.confidence
    else:
        LOG.error('Unsupported indicator type: {}, skipping.'.format(ioc.type))
        return

    pkg.add_indicator(indicator)


def get_config():
    with open('config.json') as json_config:
        config = json.load(json_config)
    cognito_config = config.get('cognito')
    crowdstrike_config = config.get('crowdstrike')
    fireeye_config = config.get('fireeye')
    system_config = config.get('system')
    return cognito_config, crowdstrike_config, fireeye_config, system_config


def set_logging(level):
    log_level = logging.DEBUG if level == 'DEBUG' else logging.INFO
    logging.basicConfig(level=log_level)
    # logging.basicConfig(filename='/var/log/indicators.log', format='%(asctime)s: %(message)s', level=logging.INFO)


def init_stix_pkg(title):
    """
    Initializes STIX package
    :param title: Title of STIX threat intel file
    :return: stixk package
    """
    pkg = STIXPackage()
    pkg.title = title
    return pkg


def write_stix(pkg, outfile):
    """
    Writes STIX pkg contents to the outfile

    :param pkg: STIX pkg
    :param outfile: output file
    """
    with open(outfile, 'wb') as fh:
        fh.write(pkg.to_xml())


@validate_cognito_config
def init_cognito_api(**kwargs):
    """
    Initializes the Cognito API
    :param kwargs: dictionary containing cognito API information configured in config.json
    :return: returns a vectra client object
    """
    vectra_client = vectra.VectraClient(url='https://' + kwargs['brain'], token=kwargs['token'])
    return vectra_client


def update_cognito_threat_feed(client, xml, feed):
    """
    Check if named feed exists and update, otherwise create and update

    :param client: initialized vectra client object
    :param xml: name of file that contains STIX TI information
    :param feed: name of threat feed
    """
    def update_feed(fid, filename, feedname):
        try:
            LOG.info('Updating Cognito Threat Feed [{}].'.format(feedname))
            client.post_stix_file(feed_id=fid, stix_file=filename)
        except FileNotFoundError:
            LOG.error('Not able to access file [{}]'.format(filename))

    feed_id = client.get_feed_by_name(name=feed)
    if feed_id:
        update_feed(feed_id, xml, feed)

    else:
        LOG.info('Creating Cognito Threat Feed [{}] for first time.'.format(feed))
        client.create_feed(name=feed, category='cnc', certainty='Low', itype='Malware Artifacts', duration=2)
        feed_id = client.get_feed_by_name(name=feed)
        update_feed(feed_id, xml, feed)


def main():
    """
    Load configurations from file
    """
    cognito_config, crowdstrike_config, fireeye_config, system_config = get_config()

    """
    Configure logging level from configuration file
    """
    set_logging(system_config['log_level'])

    """
    Initialize Vectra API client
    """
    vc = init_cognito_api(**cognito_config)

    """
    Split feeds dictionaries from CrowdStrike coinfig
    """
    feeds = crowdstrike_config.pop('feeds')

    """
    Loop forever sleeping 1 day by default
    """
    while True:
        """
        Crowdstrike
        """
        for feed in feeds.keys():
            cs_pkg = init_stix_pkg(feeds[feed]['name'])

            LOG.info('Starting collection of Crowdstrike indicators')
            try:
                cs_config = {**crowdstrike_config, **feeds[feed]}
                cs_indicators = crowdstrike.get_crowdstrike(**cs_config)
                LOG.info('Falcon returned {} total IOCs'.format(len(cs_indicators)))

                """
                Add IOCs to STIX pkg, and write pkg to xml file
                """
                for i in cs_indicators:
                    package_ioc(cs_pkg, i)

                write_stix(cs_pkg, feeds[feed]['stix_file'])

                """
                Create or update CS threat feed
                """
                update_cognito_threat_feed(vc, feeds[feed]['stix_file'], feeds[feed]['name'])

            except crowdstrike.InvalidConfigError:
                continue

        LOG.info('Process complete, sleeping for {} seconds.'.format(system_config['sleep_seconds']))
        time.sleep(system_config['sleep_seconds'])


if __name__ == '__main__':
    main()
