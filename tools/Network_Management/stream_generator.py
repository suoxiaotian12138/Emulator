import asyncio

import random

import random

class TrafficGenerator:
    def __init__(self, users):
        self.users = users

        self.templates = [
            # 明文 HTTP
            (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80),
            (b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n", "httpbin.org", 80),
            (b"POST /upload HTTP/1.1\r\nHost: data.org\r\nContent-Length: 20\r\n\r\n" + b"x" * 20, "data.org", 80),
            (b"GET /files/largefile.zip HTTP/1.1\r\nHost: files.example.com\r\nUser-Agent: curl/7.68.0\r\nConnection: close\r\n\r\n", "files.example.com", 80),
            (b"POST /api/v1/query HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"query\": \"status=active\"}", "api.example.com", 80),

            # HTTPS（常见真实服务）
            (b"GET /search?q=tor+project HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "www.google.com", 443),
            (b"GET /watch?v=oHg5SJYRHA0 HTTP/1.1\r\nHost: www.youtube.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "www.youtube.com", 443),
            (b"GET /torproject/status HTTP/1.1\r\nHost: api.twitter.com\r\nUser-Agent: curl/7.79.1\r\nConnection: close\r\n\r\n", "api.twitter.com", 443),
            (b"GET / HTTP/1.1\r\nHost: github.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "github.com", 443),
            (b"GET /user/repos HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "api.github.com", 443),
            (b"GET / HTTP/1.1\r\nHost: www.facebook.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "www.facebook.com", 443),
            (b"GET /r/privacy/comments HTTP/1.1\r\nHost: www.reddit.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "www.reddit.com", 443),
            (b"GET /wiki/Tor_(anonymity_network) HTTP/1.1\r\nHost: en.wikipedia.org\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "en.wikipedia.org", 443),
            (b"GET /questions/tagged/tor HTTP/1.1\r\nHost: stackoverflow.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", "stackoverflow.com", 443),
            (b"POST /api/v1/comments HTTP/1.1\r\nHost: api.reddit.com\r\nUser-Agent: curl/7.68.0\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"body\": \"this is a test comment\"}", "api.reddit.com", 443),
        ]

    def generate_batch(self, batch_size: int):
        """
        返回一个 batch 的四元组列表：
        (user, request_bytes, host, port)
        """
        batch = []
        selected_users = random.sample(self.users, min(batch_size, len(self.users)))
        for user in selected_users:
            content, host, port = random.choice(self.templates)
            batch.append((user, content, host, port))
        return batch


class TrafficScheduler:
    def __init__(self, users, generator: TrafficGenerator, interval: float, batch_size: int):
        self.users = users
        self.generator = generator
        self.interval = interval
        self.batch_size = batch_size
        self.running = False

    async def start(self, duration: float = None):
        self.running = True
        start_time = asyncio.get_event_loop().time()

        while self.running:
            now = asyncio.get_event_loop().time()
            if duration and (now - start_time) > duration:
                break

            batch = self.generator.generate_batch(self.batch_size)
            tasks = [user.send_stream(msg, dest) for user, msg, dest in batch]
            await asyncio.gather(*tasks)

            await asyncio.sleep(self.interval)

    def stop(self):
        self.running = False
