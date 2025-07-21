# 验证前请确保 `pip install stem`

from typing import Union
from stem.descriptor import DocumentHandler
from stem.descriptor.server_descriptor import RelayDescriptor


def validate_server_descriptor(data: Union[str, bytes], *, is_path: bool = True) -> None:
    """
    使用 Stem 对单份 Tor server‑descriptor 做语法与字段一致性校验。

    :param data: 描述符文件路径（默认）或描述符文本本身
    :param is_path: False 时把 `data` 当成文本
    :raises ValueError: 任意解析 / 校验失败
    """
    try:
        # 1) 获取文本
        text = open(data, 'r', encoding='utf‑8').read() if is_path else data
        # 2) Stem 解析；validate=True 会做 fingerprint、digest、签名等规范检查
        RelayDescriptor(text, validate=True)
        print("✅  描述符通过 Stem 校验")
    except ValueError as exc:
        # exc.line may be None for some errors
        line_no = getattr(exc, "line", None)
        msg = f"❌  校验失败: {exc}"
        if line_no is not None:
            msg += f"  (错误行号: {line_no})"
        raise ValueError(msg) from exc

# ------------------------- 用 法 -------------------------
# 1) 文件
validate_server_descriptor("md.txt")

# 2) 已在内存中的字符串
# validate_server_descriptor(desc_string, is_path = False)
