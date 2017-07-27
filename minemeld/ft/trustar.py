#  Copyright 2017-present Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import absolute_import

import logging
import os
from math import ceil

import requests
import yaml
import netaddr
import netaddr.core
import ujson as json

from . import basepoller

LOG = logging.getLogger(__name__)

_TRUSTAR_BASE = 'https://api.trustar.co'
_TRUSTAR_API_BASE = _TRUSTAR_BASE+'/api/1.2'


class Indicators(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        self.api_key = None
        self.api_secret = None

        super(Indicators, self).__init__(name, chassis, config)

    def configure(self):
        super(Indicators, self).configure()

        self.verify_cert = self.config.get('verify_cert', True)

        self.indicators_source = self.config.get('indicators_source', None)
        if self.indicators_source is not None:
            self.indicators_source = self.indicators_source.upper()
            if self.indicators_source not in ['OSINT', 'INCIDENT_REPORT']:
                raise RuntimeError('{} - invalid value for indicators_source'.format(self.name))

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        self.api_key = sconfig.get('api_key', None)
        if self.api_key is not None:
            LOG.info('%s - API key set', self.name)

        self.api_secret = sconfig.get('api_secret', None)
        if self.api_secret is not None:
            LOG.info('{} - API secret set'.format(self.name))

    def _process_item(self, item):
        indicator = item[0]
        type_ = item[1].lower()

        if type_ == 'ip':
            try:
                parsed = netaddr.IPNetwork(indicator)
            except (netaddr.AddrFormatError, ValueError):
                LOG.error('{} - Unknown IP version: {}'.format(self.name, indicator))
                return []

            if parsed.version == 4:
                type_ = 'IPv4'
            elif parsed.version == 6:
                type_ = 'IPv6'

        elif type_ == 'url':
            type_ = 'URL'

        return [[indicator, dict(type=type_)]]

    def _retrieve_access_token(self):
        url = (_TRUSTAR_BASE+'/oauth/token')

        rkwargs = dict(
            verify=self.verify_cert,
            data=dict(grant_type='client_credentials'),
            auth=(self.api_key, self.api_secret)
        )

        r = requests.post(
            url,
            **rkwargs
        )
        r.raise_for_status()

        r = json.loads(r.text)
        r = r.get('access_token', None)

        if r is None:
            raise RuntimeError('{} - No access token in Trustar response'.format(self.name))

        return r

    def _retrieve_latest_indicators(self, access_token, interval_size):
        if interval_size is None:
            interval_size = 24

        params = dict(intervalSize='{}'.format(interval_size))
        if self.indicators_source:
            params['source'] = self.indicators_source

        url = (_TRUSTAR_API_BASE+'/indicators/latest')

        rkwargs = dict(
            verify=self.verify_cert,
            params=params,
            headers={
                'Authorization': 'Bearer {}'.format(access_token)
            }
        )

        r = requests.get(
            url,
            **rkwargs
        )
        r.raise_for_status()

        r = json.loads(r.text)

        return r.get('indicators', {})

    def _ioc_generator(self, indicators):
        for it in ['IP', 'URL', 'MD5', 'SHA1', 'SHA256']:
            iocs = indicators.get(it, [])
            for ioc in iocs:
                yield (ioc, it)

    def _build_iterator(self, now):
        if not self.api_key:
            raise RuntimeError('{} - API Key not set, poll not performed'.format(self.name))

        if not self.api_secret:
            raise RuntimeError('{} - API Secret not set, poll not performed'.format(self.name))

        access_token = self._retrieve_access_token()
        LOG.info('{} - Retrieved access token'.format(self.name))

        interval_size = None
        if self.last_successful_run is not None:
            interval_size = int(ceil((now - self.last_successful_run)/(3600*1000.0)))
            interval_size = min(interval_size, 24)
        LOG.debug('{} {} => {}'.format(now, self.last_successful_run, interval_size))

        indicators = self._retrieve_latest_indicators(
            access_token=access_token,
            interval_size=interval_size
        )

        return self._ioc_generator(indicators)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Indicators, self).hup(source=source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except:
            pass
