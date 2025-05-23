




import logging







logger = logging.getLogger(__name__)




def handle_cell(self, cell):
    logger.debug(cell)
    if isinstance(cell, CellRelayConnected):
        self._connected(cell)
    elif isinstance(cell, CellRelayEnd):
        self._end(cell)
        self._call_received()
    elif isinstance(cell, CellRelayData):
        self._append(cell.data)
        self._window.deliver_dec()
        if self._window.need_sendme():
            self.send_relay(CellRelaySendMe(circuit_id=cell.circuit_id))
        self._call_received()
    elif isinstance(cell, CellRelaySendMe):
        logger.debug('Stream #%i: sendme received', self.id)
        self._window.package_inc()
    else:
        raise Exception('Unknown stream cell received: %r', type(cell))


def _connected(self, cell_connected):
    self._state = StreamState.Connected
    logger.info('Stream #%i: connected (remote ip %r)', self.id, cell_connected.address)

def _end(self, cell_end):
    logger.info('Stream #%i: remote disconnected (reason = %s)', self.id, cell_end.reason.name)
    with self._close_lock, self._data_lock:
        # For case when _end arrived later than we close
        if self._state == StreamState.Connected:
            self._state = StreamState.Disconnected

        if self.has_socket_loop:
            logger.debug('Close our sock...')
            self._loop.close_sock()
        else:
            self._has_data.set()

self._handler_mgr.subscribe_for(CellDestroy, self._on_destroy)
self._handler_mgr.subscribe_for([CellCreatedFast, CellCreated2], self._on_cell)
self._handler_mgr.subscribe_for(CellRelay, self._on_relay)