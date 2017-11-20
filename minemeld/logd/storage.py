import os
import logging
from urlparse import urlparse, parse_qs

import ujson as json
import pymysql


CURR_SCHEMA_MAJOR_VERSION = 0
CURR_SCHEMA_MINOR_VERSION = 0

CREATE_LOGS_TABLE = '''
CREATE TABLE logs (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    timestamp DOUBLE UNSIGNED NOT NULL,
    subsystem VARCHAR(256) NOT NULL,
    type VARCHAR(20) NOT NULL,
    attr VARCHAR(10240) NOT NULL,
    CHECK (JSON_VALID(attr))
);
'''

CREATE_META_TABLE = '''
CREATE TABLE IF NOT EXISTS _meta (
    major_version INT NOT NULL,
    minor_version INT NOT NULL
);
'''


LOG = logging.getLogger(__name__)


def _check_schema_version(connection_kws):
    with pymysql.connect(**connection_kws) as cursor:
        try:
            cursor.execute('SELECT `major_version`, `minor_version` FROM `_meta`')
            result = cursor.fetchone()

        except pymysql.ProgrammingError:
            return False

    LOG.info('My version: {} {}'.format(CURR_SCHEMA_MAJOR_VERSION, CURR_SCHEMA_MINOR_VERSION))
    LOG.info('Existing versions: {!r}'.format(result))

    if result is None:
        return False

    if result[0] != CURR_SCHEMA_MAJOR_VERSION:
        raise RuntimeError('Unknown Major Schema Version ({}): {} '.format(CURR_SCHEMA_MAJOR_VERSION, result[0]))

    if result[1] > CURR_SCHEMA_MINOR_VERSION:
        raise RuntimeError('Unknown Minor Schema Version ({}): {}'.format(CURR_SCHEMA_MINOR_VERSION, result[1]))

    return result[0] == CURR_SCHEMA_MAJOR_VERSION and result[1] == CURR_SCHEMA_MINOR_VERSION


def _setup_database(connection_kws):
    with pymysql.connect(**connection_kws) as cursor:
        cursor.execute('DROP TABLE IF EXISTS logs;')
        cursor.execute(CREATE_LOGS_TABLE)

        cursor.execute('DROP TABLE IF EXISTS _meta;')
        cursor.execute(CREATE_META_TABLE)
        cursor.execute(
            'INSERT INTO _meta VALUES (%s, %s);',
            (CURR_SCHEMA_MAJOR_VERSION, CURR_SCHEMA_MINOR_VERSION)
        )


def _parse_db_url():
    result = {}

    database_url = os.environ.get('MINEMELD_LOGD_DB') or 'unix://mm-logd:changeme!!!@/var/lib/mysql/mysql.sock?db=minemeld-logs'

    parsed = urlparse(database_url)

    if parsed.scheme != 'unix':
        raise RuntimeError('Invalid DB URL: {!r} - Only unix socket are supported'.format(database_url))

    # this is a bit weird, I know
    # netloc is mm-logd:changeme!!!@
    if not parsed.netloc:
        raise RuntimeError('Invalid DB URL: {!r} - No credentials provided'.format(database_url))

    username, password = parsed.netloc[:-1].split(':')
    result['user'] = username
    result['password'] = password

    if not parsed.path:
        raise RuntimeError('Invalid DB URL: {!r} - No valid unix socket path'.format(database_url))

    result['unix_socket'] = parsed.path

    params = parse_qs(parsed.query)
    for f, v in params.iteritems():
        if f not in ['db']:
            continue

        result[f] = v[0]

    return result


def connection():
    return pymysql.connect(**_parse_db_url())


def append(cursor, **kwargs):
    timestamp = kwargs.pop('created', None)
    if timestamp is None:
        timestamp = kwargs.pop('timestamp')

    subsystem = kwargs.pop('name')
    type_ = kwargs.pop('levelname')

    attr = json.dumps(kwargs)

    cursor.execute(
        'INSERT INTO logs (timestamp, subsystem, type, attr) VALUES (%s, %s, %s, %s);',
        (timestamp, subsystem, type_, attr)
    )


def initialize():
    connection_kws = _parse_db_url()

    if not _check_schema_version(connection_kws):
        LOG.info('Mismatch in database version, upgrading database')
        _setup_database(connection_kws)
