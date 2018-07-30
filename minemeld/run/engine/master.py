import gevent

import os
import logging
import shutil
import time
import signal
import multiprocessing
import math

import minemeld.schemas
from minemeld.mgmtbus import MgmtbusMaster
from minemeld.run.config import CHANGE_CONFIG, validate
from minemeld.chassis import main as chassis_main


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
        self.chassis_lock = gevent.lock.BoundedSemaphore()
        self.chassis = []

        self.mgmtbusmaster = MgmtbusMaster(
            comm_class='ZMQRedis',
            comm_config={}
        )
        self.mgmtbusmaster.start()

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

        cconfig.compute_changes(rcconfig)

        self._apply_config(cconfig)

        if rcconfig is not None:
            shutil.copyfile(
                rcpath,
                '{}.{}'.format(rcpath, int(time.time()))
            )
        shutil.copyfile(ccpath, rcpath)

    def stop(self):
        """Stop master
        """
        self.mgmtbusmaster.stop_status_monitor()
        self._cleanup()
        self.shut_down.set()

    def _apply_config(self, config):
        restart_required = self.running_config is None 
        schemas = minemeld.schemas.get()

        for cchange in config.changes:
            if cchange.change != CHANGE_CONFIG:
                restart_required = True
                break
            
            schema = next((n for n in schemas if n['id'] == cchange.nodeclass), None)
            if schema is None:
                LOG.warning('Schema for class {} not found'.format(cchange.nodeclass))
                continue
            if cchange.detail not in schema.get('config_runtime_properties', []):
                restart_required = True
                break

        if restart_required:
            self.mgmtbusmaster.stop_status_monitor()
            self._cleanup()

            nchassis = self._calc_number_of_chassis(config)
            nlists = self._split_nodes(config, nchassis)

            self.mgmtbusmaster.init(nchassis,list(config.nodes.keys()))

            with self.chassis_lock:
                # we start the new process in a clean interpreter
                # slower, but avoid issues with stale state
                multiprocessing.set_start_method('spawn')

                sigint_handler = signal.getsignal(signal.SIGINT)
                sigterm_handler = signal.getsignal(signal.SIGTERM)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)

                for g in nlists:
                    if len(g) == 0:
                        continue

                    p = multiprocessing.Process(
                        target=chassis_main,
                        args=(
                            g,
                        )
                    )
                    self.chassis.append(p)
                    p.start()

                signal.signal(signal.SIGINT, sigint_handler)
                signal.signal(signal.SIGTERM, sigterm_handler)

            self.mgmtbusmaster.wait_for_chassis(timeout=10)
            self.mgmtbusmaster.start_status_monitor()
            self.mgmtbusmaster.init_graph(config)
            self.mgmtbusmaster.start_chassis()

        else:
            # push configurations to nodes
            pass

        self.running_config = config

    def _cleanup(self):
        """Cleanup existing chassis. Checkpoints the graph and terminates the chassis
        """

        if self.mgmtbusmaster is not None:
            self.mgmtbusmaster.checkpoint_graph()

        with self.chassis_lock:
            if len(self.chassis) == 0:
                return

            for c in self.chassis:
                if not c.is_alive():
                    continue

                try:
                    os.kill(c.pid, signal.SIGUSR1)
                except OSError:
                    continue

            while sum([int(t.is_alive()) for t in self.chassis]) != 0:
                gevent.sleep(1)

            self.chassis = []

    def _calc_number_of_chassis(self, config):
        """Calculate number of chassis required for config based on MP params
        
        Args:
            config (MineMeldConfig): configuration
        
        Returns:
            int: number of chassis required
        """

        np = self.mp
        if np == 0:
            np = multiprocessing.cpu_count()
        LOG.info('multiprocessing: #cores: %d', multiprocessing.cpu_count())
        LOG.info("multiprocessing: max #chassis: %d", np)

        np = min(
            int(math.ceil(len(config.nodes)/self.npc)),
            np
        )
        LOG.info("Number of chassis: %d", np)

        return np

    def _split_nodes(self, config, num_chassis):
        """Split nodes between chassis
        
        Args:
            config (MineMeldConfig): config
            num_chassis (int): number of chassis
        
        Returns:
            list: list of dicts, one for each chassis
        """

        result = [{} for i in range(num_chassis)]

        for idx, (nid, node) in enumerate(config.nodes.items()):
            result[idx % num_chassis][nid] = node

        return result
