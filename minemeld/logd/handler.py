import time
import logging
from traceback import format_exception
from logging import Handler
from errno import EAGAIN

import zmq.green as zmq


__all__ = ['handler_factory', 'notify_fork']


HANDLERS = []
LOG_HWM = 10000
DEBUG_HWM = 10000


class MMLogHandler(Handler):
    def __init__(self):
        self.context = None
        self.socket = None
        self.debug_socket = None

        super(MMLogHandler, self).__init__()

    def emit(self, record):
        if self.context is None or self.socket is None or self.debug_socket is None:
            self._setup_sockets()

        log = {}
        log['message'] = record.getMessage()
        for fn, fv in record.__dict__.iteritems():
            if fn in ['created', 'levelname', 'name', 'process']:
                log[fn] = fv
                continue

            if fn == 'exc_info' and fv is not None:
                log[fn] = '\n'.join(format_exception(*fv))
                continue
        log['timestamp'] = time.time()

        try:
            if record.levelno <= logging.DEBUG:
                self.debug_socket.send_json(log, flags=zmq.DONTWAIT)
            else:
                self.socket.send_json(log)

        except zmq.ZMQError as e:
            if e.errno != EAGAIN:
                raise

    def flush(self):
        pass

    def notify_fork(self):
        self.close()

    def close(self):
        if self.socket is not None:
            self.socket.close(linger=0)

        if self.debug_socket is not None:
            self.debug_socket.close(linger=0)

        if self.context is not None:
            self.context.term()

        self.context = None
        self.socket = None
        self.debug_socket = None

    def _setup_sockets(self):
        if self.context is None:
            self.context = zmq.Context()

        if self.socket is None:
            self.socket = self.context.socket(zmq.PUSH)
            self.socket.set_hwm(LOG_HWM)
            self.socket.connect('ipc:///var/run/minemeld/log')

        if self.debug_socket is None:
            self.debug_socket = self.context.socket(zmq.PUSH)
            self.debug_socket.set_hwm(DEBUG_HWM)
            self.debug_socket.connect('ipc:///var/run/minemeld/log:debug')


def handler_factory():
    result = MMLogHandler()
    HANDLERS.append(result)

    return result


def notify_fork():
    for h in HANDLERS:
        h.notify_fork()
