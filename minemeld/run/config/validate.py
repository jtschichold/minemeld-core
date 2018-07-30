import os
import logging
import re

import jsonschema

import minemeld.loader
import minemeld.schemas

from .config_class import MineMeldConfig
from .prototypes import resolve_config

LOG = logging.getLogger(__name__)


def _detect_cycles(nodes):
    # using Topoligical Sorting to detect cycles in graph, see Wikipedia
    graph = {}
    S = set()
    L = []

    for n in nodes:
        graph[n] = {
            'inputs': [],
            'outputs': []
        }

    for n, v in nodes.items():
        for i in v.get('inputs', []):
            if i in graph:
                graph[i]['outputs'].append(n)
                graph[n]['inputs'].append(i)

    for n, v in graph.items():
        if len(v['inputs']) == 0:
            S.add(n)

    while len(S) != 0:
        n = S.pop()
        L.append(n)

        for m in graph[n]['outputs']:
            graph[m]['inputs'].remove(n)
            if len(graph[m]['inputs']) == 0:
                S.add(m)
        graph[n]['outputs'] = []

    nedges = 0
    for n, v in graph.items():
        nedges += len(v['inputs'])
        nedges += len(v['outputs'])

    return nedges == 0


def _validate_config(config, schemas):
    """Validate config
    
    Args:
        config (MineMeldConfig): config to validate
    
    Returns:
        list: list of errors
    """

    result = []

    nodes = config.nodes

    for n in nodes.keys():
        if re.match('^[a-zA-Z0-9_\-]+$', n) is None:  # pylint:disable=W1401
            result.append('%s node name is invalid' % n)

    for n, v in nodes.items():
        for i in v.get('inputs', []):
            if i not in nodes:
                result.append('%s -> %s is unknown' % (n, i))
                continue

            if not nodes[i].get('output', False):
                result.append('%s -> %s output disabled' %
                              (n, i))

    installed_nodes = minemeld.loader.map(minemeld.loader.MM_NODES_ENTRYPOINT)
    for n, v in nodes.items():
        nclass = v.get('class', None)
        if nclass is None:
            result.append('No class in {}'.format(n))
            continue

        mmep = installed_nodes.get(nclass, None)
        if mmep is None:
            result.append(
                'Unknown node class {} in {}'.format(nclass, n)
            )
            continue

        if not mmep.loadable:
            result.append(
                'Class {} in {} not safe to load'.format(nclass, n)
            )

        nconfig = v.get('config', {})
        schema = next((n for n in schemas if n['id'] == nclass), None)
        if schema is None:
            result.append('Class {} in {} does not have a config schema'.format(nclass, n))
            continue

        try:
            jsonschema.validate(nconfig, schema)

        except jsonschema.SchemaError as e:
            result.append('Invalid schema for class {}: {}'.format(nclass, str(e)))
        
        except jsonschema.ValidationError as e:
            result.append('Invalid config for class {} in {}: {}'.format(nclass, n, str(e)))

    if not _detect_cycles(nodes):
        result.append('loop detected')

    return result


def validate(path):
    """Load and validate config from file
    
    Args:
        path (str): filename of the config
    
    Returns:
        tuple: is_valid_?, MineMeldConfig instance
    """

    valid = True
    config = None

    if os.path.isfile(path):
        try:
            with open(path, 'r') as cf:
                config = MineMeldConfig.from_file(cf)

        except (RuntimeError, IOError, ValueError):
            LOG.exception(
                'Error loading config {}, config ignored'.format(path)
            )
            valid, config = False, None

    if valid and config is not None:
        valid = resolve_config(config)
        LOG.debug('Resolved config: {} valid: {}'.format(config, valid))

    if valid and config is not None:
        # get schemas
        schemas = minemeld.schemas.get()

        vresults = _validate_config(config, schemas)
        if len(vresults) != 0:
            LOG.error('Invalid config {}: {}'.format(
                path,
                ', '.join(vresults)
            ))
            valid = False

    return valid, config
