#!/usr/bin/env python3
"""读取 WeChat 发送链路候选偏移的 Frida 探针。

此工具只做模块与指令检查，用于为当前微信版本建立独立 profile。
"""

from __future__ import annotations

import argparse
import json
import plistlib
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = Path("/Applications/WeChat.app")
INFO_PLIST = APP / "Contents/Info.plist"
AGENT = ROOT / "native/probe_agent.js"
DEFAULT_PROFILE = ROOT / "profiles/4.1.11.53.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="检查 WeChat 内部发送 profile 的候选偏移。")
    parser.add_argument("--pid", type=int, help="WeChat 主进程 PID")
    parser.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_PROFILE,
        help="候选 profile JSON，默认使用 wechat_chatter 4.1.11.53 参考 profile",
    )
    parser.add_argument(
        "--hold",
        type=float,
        default=0.0,
        help="保持 Frida 会话的秒数；默认只执行检查后退出",
    )
    return parser.parse_args()


def find_wechat_pid() -> int:
    output = subprocess.check_output(["ps", "-axo", "pid=,command="], text=True)
    suffix = "/Applications/WeChat.app/Contents/MacOS/WeChat"
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        pid_text, command = fields
        if command == suffix:
            return int(pid_text)
    raise RuntimeError("未发现 WeChat 主进程")


def app_metadata() -> dict[str, object]:
    with INFO_PLIST.open("rb") as stream:
        info = plistlib.load(stream)
    return {
        "short_version": info.get("CFBundleShortVersionString"),
        "build": info.get("CFBundleVersion"),
    }


def main() -> int:
    args = parse_args()
    if sys.platform != "darwin":
        raise RuntimeError("该探针需要 macOS")
    if not APP.is_dir():
        raise RuntimeError(f"未找到微信应用：{APP}")

    try:
        import frida
    except ModuleNotFoundError as exc:
        raise RuntimeError("缺少 Python frida 模块；执行 python3 -m pip install --user frida") from exc

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    pid = args.pid or find_wechat_pid()

    device = frida.get_local_device()
    session = device.attach(pid)
    script = session.create_script(AGENT.read_text(encoding="utf-8"))
    script.load()
    try:
        report = script.exports_sync.inspect(profile)
        print(
            json.dumps(
                {
                    "application": app_metadata(),
                    "pid": pid,
                    "profile_file": str(args.profile),
                    "probe": report,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        if args.hold > 0:
            time.sleep(args.hold)
    finally:
        script.unload()
        session.detach()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"probe failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
