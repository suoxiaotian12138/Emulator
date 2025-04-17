from twisted.internet import reactor, defer, threads
import time
import csv
import threading
import numpy as np
import os
from queue import Queue
from collections import defaultdict
import weakref
import random


class LoopixReceiver():
    def __init__(self, loopixnode):
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
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None

        self.config_params = loopixnode.config_params
        self.lock = threading.Lock()
        self.logs = []
        self.routingtable = loopixnode.routingtable
        self.target_dir = "D:/project/Oniverse/file_pre_to_send/" + loopixnode.name
        self.output_buffer = Queue()
        self.data_buffer = defaultdict(list)
        self.storage_directory = "D:/project/Oniverse/file_received/" + loopixnode.name

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
        # print("pulling messages from {}".format(client_id))
        dummy_messages = []
        popped_messages = self.get_clients_messages(client_id)
        # print('popped messages', popped_messages)
        if len(popped_messages) < self.config_params.MAX_RETRIEVE:
            dummy_messages = self.generate_dummy_messages(
                self.config_params.MAX_RETRIEVE - len(popped_messages))
        # return popped_messages + dummy_messages
        return popped_messages

    def get_clients_messages(self, client_id):
        # print(self.storage_inbox.keys())
        if client_id in self.storage_inbox.keys():
            messages = self.storage_inbox[client_id]
            popped, rest = messages[:self.config_params.MAX_RETRIEVE], messages[self.config_params.MAX_RETRIEVE:]
            self.storage_inbox[client_id] = rest
            return popped
        return []

    def generate_dummy_messages(self, num):
        dummy_messages = [('DUMMY', self.generate_random_string(self.config_params.NOISE_LENGTH),
                           self.generate_random_string(self.config_params.NOISE_LENGTH)) for _ in range(num)]
        return dummy_messages

    @staticmethod
    def generate_random_string(length):
        return np.random.bytes(length)

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
            with open('PIDcontrolVal.csv', 'a', newline='') as outfile:
                csvW = csv.writer(outfile, delimiter=',')
                # 避免 bytes 和 str 混用的问题
                safe_logs = [
                    [col.decode() if isinstance(col, bytes) else col for col in row]
                    for row in self.logs
                ]
                csvW.writerows(safe_logs)
            self.logs = []

    def check_new_file(self):
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir)
        files = os.listdir(self.target_dir)
        receiver = random.choice(self.routingtable["clients"])

        for filename in files:
            full_path = os.path.join(self.target_dir, filename)

            if not filename.endswith(".done") and os.path.isfile(full_path):
                with open(full_path, "rb") as f:
                    content = f.read()

                # 为每个文件生成唯一 file_id
                file_id = filename[:2].upper()

                # 添加开始标志
                self.output_buffer.put((b'FILE_START:' + file_id.encode(), receiver))
                # 分片入队
                for seq, i in enumerate(range(0, len(content), self.config_params.NOISE_LENGTH)):
                    chunk = content[i:i + self.config_params.NOISE_LENGTH]
                    header = b'FILE_DATA:' + file_id.encode() + b':' + str(seq).encode()
                    self.output_buffer.put((header + b':' + chunk, receiver))

                # 添加结束标志
                self.output_buffer.put((b'FILE_END:' + file_id.encode(), receiver))

                os.rename(full_path, full_path + ".done")

        reactor.callLater(self.config_params.EXP_PARAMS_CHECK, self.check_new_file)

    def put_real_message(self, packet):
        if packet.startswith(b'FILE_START:'):
            file_id = packet[len(b'FILE_START:'):].decode()
            print(f"[Receiver] FILE_START: {file_id}")
            self.data_buffer[file_id] = []

        elif packet.startswith(b'FILE_DATA:'):
            _, file_id, seq, data = packet.split(b':', 3)
            file_id = file_id.decode()
            seq = int(seq.decode())
            self.data_buffer[file_id].append(data)


        elif packet.startswith(b'FILE_END:'):
            file_id = packet[len(b'FILE_END:'):].decode()
            print(f"[Receiver] FILE_END: {file_id}")
            self.write_file(file_id)
            del self.data_buffer[file_id]

    def write_file(self, file_id):
        """将完整文件写入storage_directory"""
        if not os.path.exists(self.storage_directory):
            os.makedirs(self.storage_directory)

        file_path = os.path.join(self.storage_directory, f"{file_id}.txt")
        print(self.data_buffer[file_id])
        with open(file_path, 'wb') as f:
            for chunk in self.data_buffer[file_id]:
                f.write(chunk)

        print(f"[Receiver] 已保存完整文件: {file_path}")
