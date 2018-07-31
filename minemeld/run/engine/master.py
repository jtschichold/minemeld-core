import gevent

import os
import sys
import logging
import shutil
import time
import signal
import multiprocessing
import subprocess
import math
import tempfile
import json

import psutil

import minemeld.schemas
from minemeld.mgmtbus import MgmtbusMaster
from minemeld.run.config import CHANGE_CONFIG, validate

from .destroy import destroy_old_nodes


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

        self.state_lock = gevent.lock.BoundedSemaphore()

        self.running_config = None
        self.chassis_lock = gevent.lock.BoundedSemaphore()
        self.chassis = []
        self.monitor_glet = gevent.spawn(self._monitor)

        # setup environment
        if not 'REQUESTS_CA_BUNDLE' in os.environ and 'MM_CA_BUNDLE' in os.environ:
            os.environ['REQUESTS_CA_BUNDLE'] = os.environ['MM_CA_BUNDLE']

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

        if self._check_disk_space(num_nodes=len(cconfig.nodes)) is None:
            LOG.error('Not enough disk space for the committed config, ignoring')
            return

        rcvalid = True
        rcconfig = self.running_config
        if rcconfig is None:
            rcvalid, rcconfig = validate(rcpath)
            LOG.info('Loading running config: {}'.format(rcvalid))
            LOG.debug('Running config: {}'.format(rcconfig))

        cconfig.compute_changes(rcconfig)

        self._apply_config(cconfig)

        destroy_old_nodes(cconfig)
        if rcconfig is not None:
            shutil.copyfile(
                rcpath,
                '{}.{}'.format(rcpath, int(time.time()))
            )
        shutil.copyfile(ccpath, rcpath)

    def stop(self):
        """Stop master
        """

        with self.state_lock:
            self._cleanup()
            self.mgmtbusmaster.stop_status_monitor()
            self.mgmtbusmaster.stop()
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
                for g in nlists:
                    if len(g) == 0:
                        continue

                    p = self._spawn_chassis(g)
                    self.chassis.append(p)

            self.mgmtbusmaster.wait_for_chassis(timeout=10)
            self.mgmtbusmaster.start_status_monitor()
            self.mgmtbusmaster.init_graph(config)
            self.mgmtbusmaster.start_chassis()

        else:
            changed_nodes = set([c.nodename for c in config.changes if c.change == CHANGE_CONFIG])
            for cnode in changed_nodes:
                try:
                    self.mgmtbusmaster.send_node_cmd(
                        nodename=cnode,
                        command='configure',
                        params={
                            'config': config.nodes[cnode].get('config', {})
                        }
                    )
                except RuntimeError as e:
                    LOG.exception('Error changing config on node {}: {}'.format(cnode, str(e)))
                    self.stop()

        self.running_config = config

    def _spawn_chassis(self, nlist):
        """Spawn chassis with a list of nodes
        
        Args:
            nlist (dict): nodes for the new chassis
        
        Returns:
            Popen: Popen instance of the new chassis
        """

        tf, tfpath = tempfile.mkstemp()

        f = os.fdopen(tf, 'w')
        json.dump(nlist, f)
        f.close()

        p = subprocess.Popen(
            [
                sys.executable,
                '-c', 'from minemeld.run.engine.chassis import run; run({!r})'.format(tfpath)
            ],
            cwd=os.getcwd()
        )

        return p

    def _is_chassis_alive(self, chassis):
        """Check if chassis is still alive
        
        Args:
            chassis (Popen): chassis process
        
        Returns:
            bool: True if chassis is alive
        """

        rc = chassis.poll()

        return rc is None

    def _cleanup(self):
        """Cleanup existing chassis. Checkpoints the graph and terminates the chassis
        """

        if self.mgmtbusmaster is not None:
            self.mgmtbusmaster.checkpoint_graph()

        with self.chassis_lock:
            if len(self.chassis) == 0:
                return

            for c in self.chassis:
                if not self._is_chassis_alive(c):
                    continue

                try:
                    os.kill(c.pid, signal.SIGUSR1)
                except OSError:
                    continue

            while sum([int(self._is_chassis_alive(c)) for t in self.chassis]) != 0:
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

    def _check_disk_space(self, num_nodes):
        """Check if there is enough disk space
        
        Args:
            num_nodes (int): number of nodes
        
        Returns:
            int: available disk space, or None if there is not enough
        """

        free_disk_per_node = int(os.environ.get(
            'MM_DISK_SPACE_PER_NODE',
            10*1024  # default: 10MB per node
        ))
        needed_disk = free_disk_per_node*num_nodes*1024
        free_disk = psutil.disk_usage('.').free

        LOG.debug('Disk space - needed: {} available: {}'.format(needed_disk, free_disk))

        if free_disk <= needed_disk:
            LOG.critical(
                ('Not enough space left on the device, available: {} needed: {}'
                ' - please delete traces, logs and old engine versions and restart').format(
                free_disk, needed_disk
                )
            )
            return None

        return free_disk

    def _monitor(self):
        """Monitor glet, check chassis status and disk space
        """

        last_disk_check = None
        while not self.shut_down.is_set():
            with self.state_lock:
                with self.chassis_lock:
                    r = [int(self._is_chassis_alive(t)) for t in self.chassis]
                    if sum(r) != len(self.chassis):
                        LOG.info("One of the chassis has stopped, exit")
                        break

                if last_disk_check is None or time.time() > last_disk_check+60:
                    last_disk_check = time.time()
                    num_nodes = 0
                    if self.running_config is not None:
                        num_nodes = len(self.running_config.nodes)
                    if self._check_disk_space(num_nodes=num_nodes) is None:
                        LOG.critical('Low disk space, stopping graph to avoid corruption')
                        break

            gevent.sleep(1.0)

        if not self.shut_down.is_set():
            self.stop()
