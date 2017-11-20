#  Copyright 2015-2016 Palo Alto Networks, Inc
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

import gevent
import gevent.monkey
from minemeld.packages import gevent_openssl  # for patching pyopenssl
gevent_openssl.monkey_patch()
gevent.monkey.patch_all(thread=False, select=False)

import os.path
import logging
import signal
import multiprocessing
import argparse
import os
import math

import psutil

import minemeld.chassis
import minemeld.mgmtbus
import minemeld.run.config
import minemeld.logd

from minemeld import __version__


ROOT_LOGGER = logging.getLogger()
MINEMELD_LOGGER = logging.getLogger('minemeld')
MASTER_LOGGER = logging.getLogger('minemeld.engine.master')


def _setup_logging(verbose):
    verbose = verbose or 'MINEMELD_DEBUG' in os.environ

    formatter = logging.Formatter(
        fmt="%(asctime)s (%(process)d)%(module)s.%(name)s"
            " %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    ROOT_LOGGER.setLevel(logging.INFO if not verbose else logging.DEBUG)

    rerrhandler = logging.StreamHandler()
    rerrhandler.setFormatter(formatter)
    rerrhandler.setLevel(logging.INFO if not verbose else logging.DEBUG)
    ROOT_LOGGER.addHandler(rerrhandler)

    mmloghandler = minemeld.logd.handler_factory()
    mmloghandler.setLevel(logging.INFO if not verbose else logging.DEBUG)
    MINEMELD_LOGGER.addHandler(mmloghandler)


def _run_chassis(chassis_num, fabricconfig, mgmtbusconfig, fts):
    # notify fork 
    minemeld.logd.notify_fork()

    logger = logging.getLogger(
        'minemeld.engine.chassis.{}'.format(chassis_num)
    )

    try:
        # lower priority to make master and web
        # more "responsive"
        os.nice(5)

        c = minemeld.chassis.Chassis(
            chassis_num,
            fabricconfig['class'],
            fabricconfig['config'],
            mgmtbusconfig
        )

        c.configure(fts)

        gevent.signal(signal.SIGUSR1, c.stop)

        while not c.fts_init():
            if c.poweroff.wait(timeout=0.1) is not None:
                break

            gevent.sleep(1)

        logger.info('Nodes initialized')

        try:
            c.poweroff.wait()
            logger.info('power off')

        except KeyboardInterrupt:
            logger.error("We should not be here !")
            c.stop()

    except:
        logger.exception('Exception in chassis main procedure')
        raise


def _check_disk_space(num_nodes):
    free_disk_per_node = int(os.environ.get(
        'MM_DISK_SPACE_PER_NODE',
        10*1024  # default: 10MB per node
    ))
    needed_disk = free_disk_per_node*num_nodes*1024
    free_disk = psutil.disk_usage('.').free

    MASTER_LOGGER.debug('Disk space - needed: {} available: {}'.format(needed_disk, free_disk))

    if free_disk <= needed_disk:
        MASTER_LOGGER.critical(
            ('Not enough space left on the device, available: {} needed: {}'
             ' - please delete traces, logs and old engine versions and restart').format(
             free_disk, needed_disk
            )
        )
        return None

    return free_disk


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Low-latency threat indicators processor"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        '--multiprocessing',
        default=0,
        type=int,
        action='store',
        metavar='NP',
        help='enable multiprocessing. NP is the number of chassis, '
             '0 to use two chassis per machine core (default)'
    )
    parser.add_argument(
        '--nodes-per-chassis',
        default=15.0,
        type=float,
        action='store',
        metavar='NPC',
        help='number of nodes per chassis (default 15)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='verbose'
    )
    parser.add_argument(
        'config',
        action='store',
        metavar='CONFIG',
        help='path of the config file or of the config directory'
    )
    return parser.parse_args()


def _setup_environment(config):
    # make config dir available to nodes
    cdir = config
    if not os.path.isdir(cdir):
        cdir = os.path.dirname(config)
    os.environ['MM_CONFIG_DIR'] = cdir

    if 'REQUESTS_CA_BUNDLE' not in os.environ and 'MM_CA_BUNDLE' in os.environ:
        os.environ['REQUESTS_CA_BUNDLE'] = os.environ['MM_CA_BUNDLE']


def main():
    mbusmaster = None
    processes_lock = None
    processes = None
    disk_space_monitor_glet = None

    def _cleanup():
        if mbusmaster is not None:
            mbusmaster.checkpoint_graph()

        if processes_lock is None:
            return

        with processes_lock:
            if processes is None:
                return

            for p in processes:
                if not p.is_alive():
                    continue

                try:
                    os.kill(p.pid, signal.SIGUSR1)
                except OSError:
                    continue

            while sum([int(t.is_alive()) for t in processes]) != 0:
                gevent.sleep(1)

    def _sigint_handler():
        MASTER_LOGGER.info('SIGINT received')
        _cleanup()
        signal_received.set()

    def _sigterm_handler():
        MASTER_LOGGER.info('SIGTERM received')
        _cleanup()
        signal_received.set()

    def _disk_space_monitor(num_nodes):
        while True:
            if _check_disk_space(num_nodes=num_nodes) is None:
                _cleanup()
                signal_received.set()
                break

            gevent.sleep(60)

    args = _parse_args()

    _setup_logging(args.verbose)

    MASTER_LOGGER.info("Starting mm-run.py version %s", __version__)
    MASTER_LOGGER.info("mm-run.py arguments: %s", args)

    _setup_environment(args.config)

    # load and validate config
    config = minemeld.run.config.load_config(args.config)

    MASTER_LOGGER.info("mm-run.py config: %s", config)

    if _check_disk_space(num_nodes=len(config.nodes)) is None:
        MASTER_LOGGER.critical('Not enough disk space available, exit')
        return 2

    np = args.multiprocessing
    if np == 0:
        np = multiprocessing.cpu_count()
    MASTER_LOGGER.info('multiprocessing: #cores: %d', multiprocessing.cpu_count())
    MASTER_LOGGER.info("multiprocessing: max #chassis: %d", np)

    npc = args.nodes_per_chassis
    if npc <= 0:
        MASTER_LOGGER.critical('nodes-per-chassis should be a positive integer')
        return 2

    np = min(
        int(math.ceil(len(config.nodes)/npc)),
        np
    )
    MASTER_LOGGER.info("Number of chassis: %d", np)

    ftlists = [{} for j in range(np)]
    j = 0
    for ft in config.nodes:
        pn = j % len(ftlists)
        ftlists[pn][ft] = config.nodes[ft]
        j += 1

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    processes = []
    for idx, g in enumerate(ftlists):
        if len(g) == 0:
            continue

        p = multiprocessing.Process(
            target=_run_chassis,
            args=(
                idx,
                config.fabric,
                config.mgmtbus,
                g
            )
        )
        processes.append(p)
        p.start()

    processes_lock = gevent.lock.BoundedSemaphore()
    signal_received = gevent.event.Event()

    gevent.signal(signal.SIGINT, _sigint_handler)
    gevent.signal(signal.SIGTERM, _sigterm_handler)

    try:
        mbusmaster = minemeld.mgmtbus.master_factory(
            config=config.mgmtbus['master'],
            comm_class=config.mgmtbus['transport']['class'],
            comm_config=config.mgmtbus['transport']['config'],
            nodes=config.nodes.keys(),
            num_chassis=len(processes)
        )
        mbusmaster.start()
        mbusmaster.wait_for_chassis(timeout=10)
        # here nodes are all CONNECTED, fabric and mgmtbus up, with mgmtbus
        # dispatching and fabric not dispatching
        mbusmaster.start_status_monitor()
        mbusmaster.init_graph(config)
        # here nodes are all INIT
        mbusmaster.start_chassis()
        # here nodes should all be starting

    except Exception:
        MASTER_LOGGER.exception('Exception initializing graph')
        _cleanup()
        raise

    disk_space_monitor_glet = gevent.spawn(_disk_space_monitor, len(config.nodes))

    try:
        while not signal_received.wait(timeout=1.0):
            with processes_lock:
                r = [int(t.is_alive()) for t in processes]
                if sum(r) != len(processes):
                    MASTER_LOGGER.info("One of the chassis has stopped, exit")
                    break

    except KeyboardInterrupt:
        MASTER_LOGGER.info("Ctrl-C received, exiting")

    except:
        MASTER_LOGGER.exception("Exception in main loop")

    if disk_space_monitor_glet is not None:
        disk_space_monitor_glet.kill()
