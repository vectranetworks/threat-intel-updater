import logging.handlers
import json
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


class IOC:
    """
    Class to create an IOC object
    """
    def __init__(self, ioc=None, ioc_type=None, ioc_label=None):
        self.value = ioc if ioc is not None else []
        self.type = ioc_type if (ioc_type in ['ip', 'domain']) else 'undef'
        self.label = ioc_label if ioc_label is not None else []


def validate_config(func):
    def check_config(**kwargs):
        if all(value is not '' for value in kwargs.values()):
            return func()
        else:
            LOG.info('Configuration not valid skipping. {}'.format(kwargs))
            return
    return check_config


def validate_cognito_config(func):
    def check_cognito_config(**kwargs):
        if all(value is not '' for value in kwargs.values()):
            return func()
        else:
            raise Exception('Ensure config.json has valid cognito configuration.')
    return check_cognito_config


def package_ioc(pkg, indicator_type, value):
    indicator = Indicator()
    if indicator_type == 'ip':
        address = Address()
        address.address_value = value
        address.address_value.condition = "Equals"
        indicator.observable = Observable(address)
    elif indicator_type == 'domain':
        domain = DomainName()
        domain.value = value
        indicator.observable = Observable(domain)
    else:
        LOG.error('Unsupported indicator type: {}, skipping.'.format(indicator_type))
        return

    pkg.add_indicator(indicator)


def open_config():
    with open('config.json') as json_config:
        config = json.load(json_config)
    cognito_config = config.get('cognito')
    crowdstrike_config = config.get('crowdstrike')
    fireeye_config = config.get('fireeye')
    return cognito_config, crowdstrike_config, fireeye_config


def main():
    log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    cognito_config, crowdstrike_config, fireeye_config = open_config()
    while True:
        @validate_config

    #  Loop through gathering IOCs, creating STIX file, uploading to Cognito


if __name__ == '__main__':
    main()
