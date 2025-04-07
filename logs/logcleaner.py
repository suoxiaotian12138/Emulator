import os


def clean_logs(directory="."):
    """
    删除指定目录下的所有 .log 文件。

    :param directory: 要清理的目录，默认为当前目录
    """
    log_files = [f for f in os.listdir(directory) if f.endswith(".log")]

    if not log_files:
        print("没有找到任何 .log 文件。")
        return

    for log_file in log_files:
        log_path = os.path.join(directory, log_file)
        try:
            os.remove(log_path)
            print(f"已删除: {log_path}")
        except Exception as e:
            print(f"无法删除 {log_path}: {e}")


if __name__ == "__main__":
    clean_logs()
