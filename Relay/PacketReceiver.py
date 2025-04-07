from twisted.internet import reactor, defer, threads
import time
import csv
import threading
import numpy as np




class LoopixReceiver():
    def __init__(self, config_params, message_maker):
        self.queue = []
        self.consumers = []

        self.target = 0.5

        self.Kp = 3.0  # 2
        self.Ki = 0.0  # 1
        self.Kd = 15.0  # 5

        self.drop = 0
        self.sum_Error = []
        self.timings = 0.0
        self.prev_Error = 0.0

        self.config_params = config_params
        self.message_maker = message_maker
        self.lock = threading.Lock()
        self.logs = []

    def __contains__(self, key):
        return key in self.queue

    def put(self, obj):
        insert_t = time.time()
        self.queue.append((insert_t, obj))

        self._process()

    def get(self):
        d = defer.Deferred()
        self.consumers += [d]

        reactor.callLater(0.0, self._process)
        return d

    def setup_storage_clients(self):
        self.storage_inbox = {}
        self.clients = {}

    def put_into_storage(self, client_id, packet):
        try:
            self.storage_inbox[client_id].append(packet)
        except KeyError as _:
            self.storage_inbox[client_id] = [packet]

    def pull_messages(self, client_id):
        dummy_messages = []
        popped_messages = self.get_clients_messages(client_id)
        if len(popped_messages) < self.config_params.MAX_RETRIEVE:
            dummy_messages = self.message_maker.generate_dummy_messages(
                self.config_params.MAX_RETRIEVE - len(popped_messages))
        return popped_messages + dummy_messages

    def get_clients_messages(self, client_id):
        if client_id in self.storage_inbox.keys():
            messages = self.storage_inbox[client_id]
            popped, rest = messages[:self.config_params.MAX_RETRIEVE], messages[self.config_params.MAX_RETRIEVE:]
            self.storage_inbox[client_id] = rest
            return popped
        return []

    def _process(self):
        try:
            while self.consumers != [] and self.queue != []:
                d = self.consumers.pop(0)
                obj = self.queue.pop(0)
                dt = threads.deferToThread(self._process_in_thread, d, obj)
            # reactor.callInThread(self._process_in_thread, d, obj)
        except Exception as e:
            print(str(e))

    def _process_in_thread(self, d, obj):
        inserted_time, message = obj
        start_time = time.time()
        d.callback(message)
        end_time = time.time()
        # self.timings = 0 * self.timings + 1 * (start_time - inserted_time)

        # the proportional term produces an output value that is proportional to the current error value
        # P = self.timings - self.target
        with self.lock:
            P = (start_time - inserted_time) - self.target

            # the contribution from the integral term is proportional to both the magnitude of the error and the duration of the error
            # I = 0.8 * self.sum_Error + 0.2 * P # the integral in a PID controller is the sum of the instantaneous error over time and gives the accumulated offset that should have been corrected previously
            self.sum_Error.append(P)
            self.sum_Error = self.sum_Error[-1000:]
            I = sum(self.sum_Error)

            # Derivative action predicts system behavior and thus improves settling time and stability of the system
            # D = P - I # the derivative of the process error is calculated by determining the slope of the error over time
            D = P - self.prev_Error

            self.prev_Error = P

            self.drop += self.Kp * P + self.Ki * I + self.Kd * D
            drop_tmp = self.drop
            # save_drop = self.drop

            self.drop = max(0.0, self.drop)

            tmp = np.random.poisson(self.drop)
            q_len = len(self.queue)
            del self.queue[:int(tmp)]

            # print "===== Delay: %.2f ==== Latency: %.2f ===== Estimate: %.2f =====" % (start_time - inserted_time, end_time - start_time, self.timings)
            # print "====Before queue len: %.2f ==== Queue Len: %.2f ==== Drop Len: %.2f ======" % (q_len, len(self.queue), self.drop)

            dataTmp = [tmp, P, I, D, q_len, start_time - inserted_time]
            self.log(dataTmp)

    def log(self, data):
        self.logs.append(data)
        if len(self.logs) > 1000:
            with open('PIDcontrolVal.csv', 'ab') as outfile:
                csvW = csv.writer(outfile, delimiter=',')
                csvW.writerows(self.logs)
            self.logs = []


