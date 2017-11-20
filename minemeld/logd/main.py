import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import logging
from errno import EAGAIN
from logging import getLogger

import zmq.green as zmq
import zmq.utils.monitor

import storage


ROOT_LOGGER = getLogger()


ZMQ_EVENT_ACCEPTED = 32
ZMQ_EVENT_DISCONNECTED = 512


class MMLogReceiver(object):
    def __init__(self):
        self._monitor_glet = None
        self.connected = set()

    def run(self):
        socket = None
        debug_socket = None
        context = None
        connection = None

        while True:
            try:
                if context is None:
                    context = zmq.Context()

                if socket is None:
                    socket = context.socket(zmq.PULL)
                    socket.bind('ipc:///var/run/minemeld/log')

                if debug_socket is None:
                    debug_socket = context.socket(zmq.PULL)
                    debug_socket.bind('ipc:///var/run/minemeld/log:debug')

                if connection is None:
                    connection = storage.connection()

                self._consume_logs(socket, debug_socket, connection)

            except Exception:
                ROOT_LOGGER.exception('Error in MMLogReceiver')

                if socket is not None:
                    socket.close()

                if debug_socket is not None:
                    debug_socket.close()

                if context is not None:
                    context.term()

                if connection is not None:
                    connection.close()

                socket = None
                debug_socket = None
                context = None
                connection = None

                gevent.sleep(60)

    def _consume(self, socket):
        while True:
            try:
                log = socket.recv_json(flags=zmq.DONTWAIT)
                yield log

            except zmq.ZMQError as e:
                if e.errno != EAGAIN:
                    raise

                return

    def _consume_logs(self, socket, dsocket, connection):
        cursor = None
        num_logs = 0

        while True:
            round_logs = 0

            if cursor is None:
                num_logs = 0
                cursor = connection.cursor()

            for log in self._consume(socket):
                storage.append(cursor, **log)
                num_logs += 1
                round_logs += 1

                if num_logs == 1024:
                    connection.commit()
                    num_logs = 0

            for nlog, log in enumerate(self._consume(dsocket)):
                storage.append(cursor, **log)
                num_logs += 1
                round_logs += 1

                if num_logs == 1024:
                    connection.commit()
                    num_logs = 0

                if nlog == 100:  # max 100 debug before checking the hp logs
                    break

            if round_logs == 0:
                gevent.sleep(0.5)

            else:
                connection.commit()
                num_logs = 0


def main():
    logging.basicConfig(level=logging.DEBUG)

    storage.initialize()

    logrecvr = MMLogReceiver()
    logrecvr.run()
