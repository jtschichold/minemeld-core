import os
import time
from collections import deque
from contextlib import contextmanager

import yaml
import gevent
import xmlrpclib
import supervisor.xmlrpc
from blinker import signal

from . import config
from . import utils
from .mmrpc import MMMaster
from .mmrpc import MMRpcClient
from .supervisorclient import MMSupervisor
from .logger import LOG


IN_COMMIT = False
_RESTART_GLET = None


def _send_status_signal(source, status):
    s = signal('mm-status')
    if not bool(s.receivers):
        return

    s.send(
        source,
        data={
            'status': status,
            'timestamp': int(time.time()*1000)
        }
    )


def _signal_commit_status(status=False):
    _send_status_signal(
        source='<commit>',
        status=status
    )


class ContextManagerStack(object):
    def __init__(self):
        self._stack = deque()

    def enter(self, cm):
        result = cm.__enter__()
        self._stack.append(cm.__exit__)

        return result

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        while self._stack:
            cb = self._stack.pop()
            cb(*exc_info)


def _restart_engine():
    LOG.info('Restarting minemeld-engine')

    supervisorurl = config.get('SUPERVISOR_URL',
                               'unix:///var/run/supervisor.sock')
    sserver = xmlrpclib.ServerProxy(
        'http://127.0.0.1',
        transport=supervisor.xmlrpc.SupervisorTransport(
            None,
            None,
            supervisorurl
        )
    )

    try:
        result = sserver.supervisor.stopProcess('minemeld-engine', False)
        if not result:
            LOG.error('Stop minemeld-engine returned False')
            return

    except xmlrpclib.Fault as e:
        LOG.error('Error stopping minemeld-engine: {!r}'.format(e))

    LOG.info('Stopped minemeld-engine for API request')

    now = time.time()
    info = None
    while (time.time()-now) < 60*10*1000:
        info = sserver.supervisor.getProcessInfo('minemeld-engine')
        if info['statename'] in ('FATAL', 'STOPPED', 'UNKNOWN', 'EXITED'):
            break
        gevent.sleep(5)
    else:
        LOG.error('Timeout during minemeld-engine restart')
        return

    sserver.supervisor.startProcess('minemeld-engine', False)
    LOG.info('Started minemeld-engine')

    now = time.time()
    info = None
    while (time.time()-now) < 60*10*1000:
        info = sserver.supervisor.getProcessInfo('minemeld-engine')
        if info['statename'] in ('RUNNING'):
            break
        gevent.sleep(5)
    else:
        LOG.error('Timeout during minemeld-engine restart')
        return


def _is_list_equal(A, B):
    # we assume that items have all the same type
    # and that if the type is int or str, unicode
    # then it's order independent, otherwise order matters
    if len(A) != len(B):
        return False

    if len(A) == 0:
        return True

    if isinstance(A[0], str) or isinstance(A[0], int) or \
       isinstance(A[0], float) or isinstance(A[0], unicode):
        # we sort in palce as these are just copies
        A.sort()
        B.sort()

    for idx in xrange(len(A)):
        if not _is_equal(A[idx], B[idx]):
            return False

    return True


def _is_dict_equal(A, B):
    A_keys = A.keys()
    B_keys = B.keys()

    if not _is_list_equal(A_keys, B_keys):
        return False

    for key in A_keys:
        if not _is_equal(A[key], B[key]):
            return False

    return True


def _is_equal(A, B):
    gevent.sleep(0)

    if isinstance(A, str):
        A = unicode(A, 'utf-8')
    if isinstance(B, str):
        B = unicode(B, 'utf-8')

    if type(A) != type(B):
        return False

    if A is None:
        return True

    if isinstance(A, bool):
        return A == B

    if isinstance(A, str) or isinstance(A, unicode):
        return A == B

    if isinstance(A, int) or isinstance(A, float):
        return A == B

    if isinstance(A, list) or isinstance(A, tuple):
        return _is_list_equal(A, B)

    if isinstance(A, dict):
        return _is_dict_equal(A, B)

    raise RuntimeError('Unhandled type {!r} in _is_equal'.format(type(A)))


def _load_current():
    rcpath = utils.running_config_path()
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    if rcconfig is None:
        rcconfig = {}

    side_configs = {}
    nodes = rcconfig.get('nodes', {})
    for idx, (node_id, nodevalue) in enumerate(nodes.iteritems()):
        sconfig = utils.side_config(node_id)
        if sconfig is not None:
            side_configs[node_id] = sconfig

    pipelines = utils.pipelines()

    return (rcconfig, side_configs, pipelines)


@contextmanager
def dump_yaml_file(target, content):
    LOG.info('COMMIT - Dump file {!r}'.format(target))

    with open(target, 'w') as f:
        yaml.safe_dump(
            content,
            f,
            encoding='utf-8',
            default_flow_style=False
        )

    try:
        yield

    except:
        utils.safe_remove(target)


@contextmanager
def move_file(src, dest):
    LOG.info('COMMIT - Move file {!r} => {!r}'.format(src, dest))

    temp_file = None
    if os.path.isfile(dest):
        temp_file = '{}.tmp'.format(dest)
        utils.safe_remove(temp_file)
        os.rename(dest, temp_file)

    os.rename(src, dest)

    try:
        yield

    except:
        if temp_file is not None:
            os.rename(temp_file, dest)

    else:
        utils.safe_remove(temp_file)


def real_commit(new_config, new_side_configs, new_pipelines):
    ccpath = utils.committed_config_path()

    current_config, current_side_configs, current_pipelines = _load_current()

    # check what has changed
    config_changed = not _is_equal(
        current_config.get('nodes', {}),
        new_config.get('nodes', {})
    )
    side_configs_changed = not _is_equal(current_side_configs, new_side_configs)
    pipelines_changed = not _is_equal(current_pipelines, new_pipelines)

    if not (config_changed or side_configs_changed or pipelines_changed):
        return (True, 'no changes')

    if config_changed:
        info = MMSupervisor.supervisor.getProcessInfo('minemeld-engine')
        if info['statename'] == 'STARTING' or info['statename'] == 'STOPPING':
            return (False, 'MineMeld engine is {}'.format(info['statename']))

    side_configs_modified = []
    if side_configs_changed:
        for nodeid, sconfig in new_side_configs.iteritems():
            if nodeid not in current_side_configs:
                side_configs_modified.append(nodeid)

            elif not _is_equal(current_side_configs[nodeid], new_side_configs[nodeid]):
                side_configs_modified.append(nodeid)

    LOG.info('COMMIT - Changes: config: {} side_configs: {} pipelines: {}'.format(
        config_changed,
        side_configs_changed,
        pipelines_changed
    ))

    with ContextManagerStack() as cmstack:
        if config_changed:
            cmstack.enter(dump_yaml_file(
                target='{}.new'.format(ccpath),
                content=new_config
            ))

        if side_configs_changed:
            for nodeid in side_configs_modified:
                cmstack.enter(dump_yaml_file(
                    target='{}.new'.format(utils.side_config_path(nodeid)),
                    content=new_side_configs[nodeid]
                ))

        if pipelines_changed:
            cmstack.enter(dump_yaml_file(
                target='{}.new'.format(utils.pipelines_path()),
                content=new_pipelines
            ))

        if config_changed:
            cmstack.enter(move_file(src='{}.new'.format(ccpath), dest=ccpath))

        if side_configs_changed:
            for nodeid in side_configs_modified:
                cmstack.enter(move_file(
                    src='{}.new'.format(utils.side_config_path(nodeid)),
                    dest=utils.side_config_path(nodeid)
                ))

        if pipelines_changed:
            cmstack.enter(move_file(
                src='{}.new'.format(utils.pipelines_path()),
                dest=utils.pipelines_path()
            ))

        if config_changed:
            _RESTART_GLET = gevent.spawn(_restart_engine)
            _RESTART_GLET.link(lambda x: _signal_commit_status(False))

        elif side_configs_changed:
            status = MMMaster.status()
            tr = status.get('result', None)
            if tr is None:
                LOG.error('COMMIT - Error retrieving status from mgmtbus master')
                return (False, 'Error signaling nodes')

            for nodeid in side_configs_modified:
                nname = 'mbus:slave:'+nodeid
                if nname not in tr:
                    LOG.error('COMMIT - Unknown node {}'.format(nodeid))
                    continue

                params = {
                    'source': 'minemeld-web',
                    'signal': 'hup'
                }

                MMRpcClient.send_cmd(
                    target=nodeid,
                    method='signal',
                    params=params
                )
                LOG.info('COMMIT - hup sent to {}'.format(nodeid))
                gevent.sleep(0)

    return (True, 'Done')


def do_commit(new_config, new_side_configs, new_pipelines):
    global IN_COMMIT
    global _RESTART_GLET

    if IN_COMMIT:
        return (False, 'commit in progress')
    IN_COMMIT = True
    _RESTART_GLET = None

    _signal_commit_status(True)

    try:
        result = real_commit(
            new_config=new_config,
            new_side_configs=new_side_configs,
            new_pipelines=new_pipelines
        )

    finally:
        if _RESTART_GLET is None:
            IN_COMMIT = False
            _signal_commit_status(False)

    return result
