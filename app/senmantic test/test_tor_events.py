import os
import time
import threading
import tempfile
from datetime import datetime

import paramiko
from stem.control import Controller
import stem.connection

# ================== 配置区 ==================

VM_HOST = "192.168.66.10"       # 虚拟机 IP
VM_SSH_PORT = 22
VM_SSH_USER = "root"
VM_SSH_PASSWORD = "sf5538177"

# 事件日志输出目录（在 Windows 本机）
LOG_DIR = r"D:\project\Oniverse_refactor\app\senmantic test\tor_logs_remote"

# 只监控这些容器名（None 表示不过滤，监控所有 running 容器里“看起来像 tor 的”）
# 建议你保持默认：只包含 tor-relay / tor-exit / tor-dir 等
NAME_KEYWORDS = ("tor-", "tor-relay", "tor-exit", "tordir", "tor-dir", "tor-authority")

# 订阅：Tor 日志 + relay 侧稳定可见事件
EVENTS = [
    # "NOTICE", "WARN", "ERR", "INFO", "DEBUG",
    "ORCONN", "BW", "STATUS_SERVER",
]

# ================== 工具函数 ==================

def log_global(msg: str):
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    print(f"[{now}] {msg}")


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def ssh_connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        VM_HOST,
        port=VM_SSH_PORT,
        username=VM_SSH_USER,
        password=VM_SSH_PASSWORD,
    )
    return client


def ssh_exec(ssh: paramiko.SSHClient, cmd: str) -> str:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    if err.strip():
        log_global(f"[SSH STDERR] cmd={cmd!r} err={err.strip()}")
    return out


def _looks_like_tor_container(name: str) -> bool:
    low = name.lower()
    return any(k in low for k in NAME_KEYWORDS)


def discover_tor_containers(ssh: paramiko.SSHClient):
    """
    返回:
    [
      {"name": "...", "host_port": 9101, "cookie_path": "/var/lib/docker/volumes/.../_data/control_auth_cookie"},
      ...
    ]
    """
    out = ssh_exec(ssh, "docker ps --format '{{.Names}}'")
    names = [line.strip() for line in out.splitlines() if line.strip()]

    # 过滤“像 tor 的容器”
    tor_names = [n for n in names if _looks_like_tor_container(n)]
    tor_names.sort()

    result = []
    for name in tor_names:
        # 1) 解析 ControlPort 映射端口（容器 9051 -> host_port）
        port_out = ssh_exec(ssh, f"docker port {name} 9051/tcp || true").strip()
        if not port_out:
            log_global(f"[WARN] {name} 未映射 9051/tcp，跳过")
            continue

        host_port = None
        for part in port_out.split():
            if ":" in part:
                try:
                    host_port = int(part.rsplit(":", 1)[1])
                    break
                except ValueError:
                    pass
        if host_port is None:
            log_global(f"[WARN] 无法解析 {name} 的 docker port 输出: {port_out!r}")
            continue

        # 2) 找 /var/lib/tor 的宿主机挂载目录 (Mount.Source)
        inspect_cmd = (
            "docker inspect "
            f"{name} --format "
            "'{{range .Mounts}}{{if eq .Destination \"/var/lib/tor\"}}{{.Source}}{{end}}{{end}}'"
        )
        mount_src = ssh_exec(ssh, inspect_cmd).strip().strip("'").strip()
        if not mount_src:
            log_global(f"[WARN] {name} 未找到 /var/lib/tor 挂载点，跳过")
            continue

        cookie_path = mount_src.rstrip("/") + "/control_auth_cookie"

        result.append(
            {
                "name": name,
                "host_port": host_port,
                "cookie_path": cookie_path,
                "docker_port_raw": port_out,
                "mount_src": mount_src,
            }
        )

    return result


def read_cookie_bytes(ssh: paramiko.SSHClient, cookie_path: str) -> bytes:
    sftp = ssh.open_sftp()
    try:
        with sftp.open(cookie_path, "rb") as f:
            return f.read()
    finally:
        sftp.close()


# ================== 监控线程 ==================

class NodeMonitor(threading.Thread):
    def __init__(self, name: str, host: str, port: int, cookie_bytes: bytes):
        super().__init__(daemon=True)
        self.name = name
        self.host = host
        self.port = port
        self.cookie_bytes = cookie_bytes
        self.stop_flag = threading.Event()
        self.log_file_path = os.path.join(LOG_DIR, f"{self.name}.log")

    def _append_line(self, line: str):
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

    def run(self):
        try:
            self._run_impl()
        except Exception as e:
            log_global(f"[ERROR] NodeMonitor({self.name}) crashed: {e!r}")
            ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
            self._append_line(f"{ts} [FATAL] monitor crashed: {e!r}\n")

    def _run_impl(self):
        log_global(f"[{self.name}] connecting {self.host}:{self.port} ...")

        with Controller.from_port(address=self.host, port=self.port) as controller:
            # 写启动标志
            ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
            self._append_line(f"{ts} [{self.name}] MONITOR_STARTED\n")

            # ==== cookie authenticate ====
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(self.cookie_bytes)
                tmp_path = tmp.name

            try:
                try:
                    stem.connection.authenticate_cookie(controller, tmp_path)
                    log_global(f"[{self.name}] authenticate_cookie: OK")
                except Exception as e:
                    log_global(f"[{self.name}] authenticate_cookie: FAIL {e!r}")
                    ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
                    self._append_line(f"{ts} [AUTH_FAIL] {e!r}\n")
                    raise
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

            # 自证身份（防止连错实例）
            try:
                nick = controller.get_conf("Nickname", default="(none)")
            except Exception:
                nick = "(unknown)"
            try:
                fp = controller.get_info("fingerprint")
            except Exception:
                fp = "(unknown)"

            log_global(f"[{self.name}] connected tor nickname={nick} fingerprint={fp}")
            ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
            self._append_line(f"{ts} [IDENT] nickname={nick} fingerprint={fp}\n")

            # 显式 SETEVENTS，并拿回包
            controller.add_event_listener(self._on_event, *EVENTS)
            cmd = "SETEVENTS " + " ".join(EVENTS)
            resp = controller.msg(cmd)
            log_global(f"[{self.name}] {cmd} resp: {resp}")
            ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
            self._append_line(f"{ts} [CTRL] {cmd} resp={resp}\n")

            # 强制产生日志/事件，确保你立刻看到输出
            dump_resp = controller.msg("SIGNAL DUMP")
            log_global(f"[{self.name}] SIGNAL DUMP resp: {dump_resp}")
            ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
            self._append_line(f"{ts} [CTRL] SIGNAL DUMP resp={dump_resp}\n")

            # 进入循环
            log_global(f"[{self.name}] monitoring ... (events: {', '.join(EVENTS)})")
            while not self.stop_flag.is_set():
                time.sleep(1.0)

    def _on_event(self, event):
        try:
            ts = getattr(event, "arrived_at", time.time())
            ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

            etype = getattr(event, "event_type", None) or type(event).__name__

            # 1) Tor 日志事件：INFO/NOTICE/WARN/ERR/DEBUG -> LogEvent
            # Stem 的 LogEvent 有 message/runlevel
            if hasattr(event, "message"):
                level = getattr(event, "runlevel", None) or getattr(event, "level", None) or "LOG"
                msg = event.message.strip()
                line = f"{ts_str} [{level}] {msg}\n"
                self._append_line(line)
                return

            # 2) 其它事件：优先 raw_content()（最接近 Tor 控制协议原文）
            if hasattr(event, "raw_content") and callable(event.raw_content):
                raw = " | ".join([s.strip() for s in event.raw_content() if s.strip()])
                line = f"{ts_str} [{etype}] {raw}\n"
                self._append_line(line)
                return

            # 3) 兜底：尽量不要写 object 地址
            # Stem event 通常有 __dict__，写成 key=value
            if hasattr(event, "__dict__"):
                items = []
                for k, v in event.__dict__.items():
                    if k.startswith("_"):
                        continue
                    items.append(f"{k}={v!r}")
                payload = " ".join(items) if items else repr(event)
                line = f"{ts_str} [{etype}] {payload}\n"
                self._append_line(line)
                return

            line = f"{ts_str} [{etype}] {repr(event)}\n"
            self._append_line(line)

        except Exception as e:
            err_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._append_line(f"{err_ts} [ERROR] _on_event failed: {e!r}\n")

    def stop(self):
        self.stop_flag.set()


# ================== 主流程 ==================

def main():
    ensure_log_dir()
    log_global("=== Remote Tor Docker Control Collector ===")
    log_global(f"VM_HOST = {VM_HOST}")
    log_global(f"LOG_DIR = {LOG_DIR}")

    ssh = None
    monitors = []

    try:
        ssh = ssh_connect()
        log_global("已通过 SSH 连接到虚拟机")

        nodes = discover_tor_containers(ssh)
        if not nodes:
            log_global("未发现可监控的 tor 容器（请检查 NAME_KEYWORDS / 容器名 / docker ps）")
            return

        log_global("将监控这些容器：")
        for n in nodes:
            log_global(
                f"  - {n['name']} 9051->host:{n['host_port']} "
                f"cookie={n['cookie_path']} "
                f"(docker_port={n['docker_port_raw']!r}, mount={n['mount_src']!r})"
            )

        # 启动监控线程
        for n in nodes:
            try:
                cookie_bytes = read_cookie_bytes(ssh, n["cookie_path"])
                if len(cookie_bytes) != 32:
                    log_global(f"[WARN] {n['name']} cookie != 32 bytes (got {len(cookie_bytes)}), skip")
                    continue

                mon = NodeMonitor(
                    name=n["name"],
                    host=VM_HOST,
                    port=n["host_port"],
                    cookie_bytes=cookie_bytes,
                )
                # 关键：把事件监听器真正挂上（Stem 会用它派发 650 事件）
                # 注意：我们在 _run_impl 里用 controller.msg("SETEVENTS ...") 设置订阅
                # 但 listener 必须在 controller 上注册，所以这里不动，注册在 _run_impl 里也行。
                mon.start()
                monitors.append(mon)

            except Exception as e:
                log_global(f"[ERROR] 初始化 {n['name']} 失败: {e!r}")

        if not monitors:
            log_global("没有成功启动任何监控线程，退出")
            return

        log_global("=== 远程事件采集已启动，按 Ctrl+C 停止 ===")
        while True:
            time.sleep(2)

    except KeyboardInterrupt:
        log_global("收到 Ctrl+C，正在停止监控线程...")

    finally:
        for mon in monitors:
            mon.stop()
        if ssh is not None:
            ssh.close()
        log_global("=== 已退出 ===")


if __name__ == "__main__":
    main()
