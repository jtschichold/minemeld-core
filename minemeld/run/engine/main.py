import gevent
import gevent.monkey
from minemeld.packages import gevent_openssl  # for patching pyopenssl
gevent_openssl.monkey_patch()
gevent.monkey.patch_all(thread=False, select=False)

import os
import logging
import argparse
import functools
import signal

import minemeld.schemas
from minemeld import __version__

from .master import Master

LOG = logging.getLogger(__name__)


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
        default=int(os.environ.get('MM_MULTIPROCESSING', 0)),
        type=int,
        action='store',
        metavar='NP',
        help='enable multiprocessing. NP is the number of chassis, '
             '0 to use two chassis per machine core (default)'
    )
    parser.add_argument(
        '--nodes-per-chassis',
        default=int(os.environ.get('MM_NPC', 15)),
        type=int,
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
        help='path of the config directory'
    )
    return parser.parse_args()


def sig_handler(*args, master=None, name=None):
    """Handler for termination signals

    Args:
        master (Master): Chassis object
        name (str): signal name
    """

    LOG.info('{} received'.format(name))
    master.stop()


def reload_config(*args, master=None):
    LOG.info('HUP received, reloading config')
    minemeld.schemas.get(cache=False)  # force cache update
    master.load()


def main():
    args = _parse_args()

    # logging
    loglevel = logging.INFO
    if args.verbose or os.getenv('MM_VERBOSE'):
        loglevel = logging.DEBUG

    logging.basicConfig(
        level=loglevel,
        format="%(asctime)s (%(process)d)%(module)s.%(funcName)s"
               " %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    LOG.info("Starting mm-engine version %s", __version__)
    LOG.info("mm-engine arguments: %s", args)

    master = Master(
        mp=args.multiprocessing,
        npc=args.nodes_per_chassis,
        config_path=args.config
    )
    master.load()

    gevent.signal(signal.SIGINT, functools.partial(sig_handler, name='SIGINT', master=master))
    gevent.signal(signal.SIGTERM, functools.partial(sig_handler, name='SIGTERM', master=master))
    gevent.signal(signal.SIGHUP, functools.partial(reload_config, master=master))

    master.shut_down.wait()

    LOG.info('Master shut down, exiting...')
    return 0

"""
    _setup_environment(args.config)

    # load and validate config
    config = minemeld.run.config.load_config(args.config)

    LOG.info("mm-engine config: %s", config)

    if _check_disk_space(num_nodes=len(config.nodes)) is None:
        LOG.critical('Not enough disk space available, exit')
        return 2

    np = args.multiprocessing
    if np == 0:
        np = multiprocessing.cpu_count()
    LOG.info('multiprocessing: #cores: %d', multiprocessing.cpu_count())
    LOG.info("multiprocessing: max #chassis: %d", np)

    npc = args.nodes_per_chassis
    if npc <= 0:
        LOG.critical('nodes-per-chassis should be a positive integer')
        return 2

    np = min(
        int(math.ceil(len(config.nodes)/npc)),
        np
    )
    LOG.info("Number of chassis: %d", np)

    ftlists = [{} for j in range(np)]
    j = 0
    for ft in config.nodes:
        pn = j % len(ftlists)
        ftlists[pn][ft] = config.nodes[ft]
        j += 1

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    processes = []
    for g in ftlists:
        if len(g) == 0:
            continue

        p = multiprocessing.Process(
            target=_run_chassis,
            args=(
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
            nodes=list(config.nodes.keys()),
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
        LOG.exception('Exception initializing graph')
        _cleanup()
        raise

    disk_space_monitor_glet = gevent.spawn(_disk_space_monitor, len(config.nodes))

    try:
        while not signal_received.wait(timeout=1.0):
            with processes_lock:
                r = [int(t.is_alive()) for t in processes]
                if sum(r) != len(processes):
                    LOG.info("One of the chassis has stopped, exit")
                    break

    except KeyboardInterrupt:
        LOG.info("Ctrl-C received, exiting")

    except:
        LOG.exception("Exception in main loop")

    if disk_space_monitor_glet is not None:
        disk_space_monitor_glet.kill()
"""