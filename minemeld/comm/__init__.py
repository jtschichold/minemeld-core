from __future__ import absolute_import

from .amqp import AMQP
from .amqpredis import AMQPRedis
from .zmqredis import ZMQRedis


def factory(commclass, config):
    if commclass == 'AMQPRedis':
        return AMQPRedis(config)

    if commclass == 'ZMQRedis':
        return ZMQRedis(config)

    if commclass != 'AMQP':
        raise RuntimeError('Unknown comm class %s', commclass)

    return AMQP(config)
