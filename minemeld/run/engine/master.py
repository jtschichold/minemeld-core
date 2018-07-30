import gevent

import os
import logging

from minemeld.mgmtbus import MgmtbusMaster
from minemeld.run.config import validate


COMMITTED_CONFIG = 'committed-config.yml'
RUNNING_CONFIG = 'running-config.yml'

LOG = logging.getLogger(__name__)


class Master(object):
    def __init__(self, mp, npc, config_path):
        """Master process of the engine
        
        Args:
            mp (int): number of chassis to use. 0 to use 2 chassis per core
            npc (int): number of nodes per chassis
            config_path (str): config directory
        """

        self.mp = mp
        self.npc = npc
        self.config_path = config_path

        self.running_config = None

        self.shut_down = gevent.event.Event()

    def load(self):
        """Load committed config and apply
        """

        ccpath = os.path.join(
            self.config_path,
            COMMITTED_CONFIG
        )
        rcpath = os.path.join(
            self.config_path,
            RUNNING_CONFIG
        )

        ccvalid, cconfig = validate(ccpath)
        LOG.info('Loading committed config: {}'.format(ccvalid))
        LOG.debug('Committed config: {}'.format(cconfig))

        if not ccvalid:
            LOG.error('Invalid committed config, ignoring')
            return

        rcvalid = True
        rcconfig = self.running_config
        if rcconfig is None:
            rcvalid, rcconfig = validate(rcpath)
            LOG.info('Loading running config: {}'.format(rcvalid))
            LOG.debug('Running config: {}'.format(rcconfig))

        

    def stop(self):
        """Stop master
        """

        self.shut_down.set()
