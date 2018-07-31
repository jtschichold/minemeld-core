import gevent
import gevent.monkey
from minemeld.packages import gevent_openssl  # for patching pyopenssl
gevent_openssl.monkey_patch()
gevent.monkey.patch_all(thread=False, select=False)

import os
import signal
import logging
import json

import minemeld.chassis

LOG = logging.getLogger(__name__)


def run(ftspath):
    """Executes the chassis
    
    Args:
        ftspath (str): file with dictionary of nodes
    """

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    with open(ftspath, 'r') as f:
        fts = json.load(f)
    os.remove(ftspath)

    logging.basicConfig(level=logging.INFO)

    try:
        # lower priority to make master and web
        # more "responsive"
        os.nice(5)

        c = minemeld.chassis.Chassis(
            fabricclass='ZMQRedis',
            fabricconfig={}
        )
        c.configure(fts)

        gevent.signal(signal.SIGUSR1, c.stop)

        while not c.fts_init():
            if c.poweroff.wait(timeout=0.1) is not None:
                break

            gevent.sleep(1)

        LOG.info('Nodes initialized')

        try:
            c.poweroff.wait()
            LOG.info('power off')

        except KeyboardInterrupt:
            LOG.error("We should not be here !")
            c.stop()

    except:
        LOG.exception('Exception in chassis main procedure')
        raise
