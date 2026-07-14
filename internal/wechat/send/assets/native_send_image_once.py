#!/usr/bin/env python3
"""单次 Frida native 图片发送测试器：upload image -> send image -> cleanup。"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import random
import re
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

from native_probe import find_wechat_pid
from native_send_once import (
    build_send_payload as build_send_payload_text,
    build_text_proto,
    cleanup_frida_helpers,
    encode_varint,
    field_bytes,
    field_varint,
    progress,
    locked_print,
    shutdown_frida_runtime,
    wait_for_manual_release,
    wait_frida_helpers_gone,
    watch_wechat_health,
)

print = locked_print

ROOT = Path(__file__).resolve().parent
AGENT = ROOT / "native/image_send_agent.js"
XWECHAT_FILES = Path.home() / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
MAX_EVENT_LOG_BYTES = 8 * 1024 * 1024
# The captured upload x1 profile reserves about 178 bytes for three libc++ path
# strings. The agent now writes each actual UTF-8 size, but keeps staged paths
# below the captured capacity with a small margin so the profile never points
# at a truncated, nonexistent filename and returns -20003.
MAX_WECHAT_UPLOAD_PATH_BYTES = 176

UPLOAD_IMG_PAYLOAD_HEX = (
    '2005338c0b0000000005338c0b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000d07220890b00000026000000000000002800000000000080000000000000000000000000000000000000000000000000000000000000001300000000000000000000000000000000000000000000000001aaaaaa0100000000000000000000000000000000000000200000000000000028000000000000800000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff0055db890b000000b200000000000000b8000000000000800000000000000000000000000000000000000000000000004054db890b000000b200000000000000b800000000000080000000000000000000000000000000000000000000000000405ddb890b000000b200000000000000c00000000000008000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000000000000aaaaaa0100000000000000000000000000000000000000000000000000000000000000aaaaaaaa000000000000000000000000000000000000000000000000010000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000028000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000000000000000000000'
)


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def make_test_png(path: Path, marker: str) -> None:
    width, height = 96, 48
    raw = bytearray()
    seed = hashlib.sha256(marker.encode()).digest()
    for y in range(height):
        raw.append(0)  # filter
        for x in range(width):
            raw.extend([(x * 3 + seed[0]) % 256, (y * 5 + seed[1]) % 256, ((x + y) * 2 + seed[2]) % 256])
    data = b"\x89PNG\r\n\x1a\n"
    data += png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    data += png_chunk(b"tEXt", b"Comment\x00" + marker.encode("utf-8"))
    data += png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    data += png_chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def account_sender(account_dir: Path) -> str:
    name = account_dir.name
    first = name.find("_")
    last = name.rfind("_")
    return name[:last] if first != -1 and last > first else name


def detect_account_dir(sender_hint: str | None = None) -> tuple[str, Path]:
    candidates = [p for p in XWECHAT_FILES.glob("wxid_*") if p.is_dir() and "Backup" not in p.parts]
    if not candidates:
        raise RuntimeError(f"未找到 WeChat 账号目录：{XWECHAT_FILES}/wxid_*")
    sender_hint = (sender_hint or "").strip()
    if sender_hint:
        matched = [p for p in candidates if account_sender(p) == sender_hint]
        if not matched:
            raise RuntimeError(f"未找到 sender={sender_hint!r} 对应的 WeChat 账号目录")
        candidates = matched
    elif len(candidates) > 1:
        accounts = ", ".join(sorted(account_sender(p) for p in candidates))
        raise RuntimeError(f"检测到多个微信账号目录，无法可靠判断当前登录账号；请显式传 --sender。候选：{accounts}")
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    account_dir = candidates[0]
    return account_sender(account_dir), account_dir


def stage_image_in_wechat_container(source: Path, account_dir: Path, marker: str) -> tuple[Path, bool]:
    source = source.expanduser().resolve()
    if not source.is_file():
        raise RuntimeError(f"图片不存在：{source}")

    target_root = account_dir / "temp/chatlog_alpha/Img"
    target_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    suffix = source.suffix.lower()
    if suffix not in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}:
        suffix = ".jpg"
    target = target_root / f"cl-{time.time_ns():x}-{random.randrange(256):02x}{suffix}"
    if len(str(target).encode("utf-8")) > MAX_WECHAT_UPLOAD_PATH_BYTES:
        target_root = account_dir / "temp/cl"
        target_root.mkdir(parents=True, exist_ok=True, mode=0o755)
        target = target_root / f"{time.time_ns():x}{suffix}"
    path_bytes = len(str(target).encode("utf-8"))
    if path_bytes > MAX_WECHAT_UPLOAD_PATH_BYTES:
        raise RuntimeError(
            f"微信图片暂存路径仍过长：{path_bytes} bytes > {MAX_WECHAT_UPLOAD_PATH_BYTES}; path={target}"
        )
    shutil.copyfile(source, target)
    # WeChat can deduplicate an identical MD5 and return the old CDN object
    # without echoing its AES key. The reference wechat_chatter implementation
    # avoids that ambiguous callback by appending an ignored salt to each staged
    # image before hashing/uploading. Only the private staged copy is changed;
    # the user's source file stays untouched. Common image decoders ignore
    # trailing bytes, while the content MD5 becomes unique per send.
    with target.open("ab") as fp:
        fp.write(f"\n#chatlog_md5_salt_{time.time_ns()}_{random.randrange(10000)}#".encode("ascii"))
    target.chmod(0o644)
    return target.resolve(), True


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def parse_elapsed_seconds(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    days = 0
    if "-" in value:
        day_text, value = value.split("-", 1)
        days = int(day_text)
    parts = [int(part) for part in value.split(":")]
    if len(parts) == 2:
        hours, minutes, seconds = 0, parts[0], parts[1]
    elif len(parts) == 3:
        hours, minutes, seconds = parts
    else:
        return None
    return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)


def process_uptime_seconds(pid: int) -> float | None:
    try:
        result = subprocess.run(
            ["ps", "-o", "etime=", "-p", str(pid)],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        return parse_elapsed_seconds(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


class AttachTimeoutError(TimeoutError):
    pass


def run_with_timeout(name: str, fn, timeout: float):
    done = threading.Event()
    result: list[object] = []
    errors: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(fn())
        except BaseException as exc:  # noqa: BLE001 - preserve original attach/load failure
            errors.append(exc)
        finally:
            done.set()

    threading.Thread(target=runner, name=f"{name}-timeout-guard", daemon=True).start()
    if not done.wait(max(1.0, timeout)):
        raise AttachTimeoutError(f"{name} 超过 {timeout:.0f} 秒仍未返回")
    if errors:
        raise errors[-1]
    return result[0] if result else None


def attach_and_load_agent(frida_module, pid: int, agent_path: Path, on_message, timeout: float):
    device = run_with_timeout("frida.get_local_device", frida_module.get_local_device, timeout)
    session = run_with_timeout("frida.attach", lambda: device.attach(pid), timeout)
    script = run_with_timeout("frida.create_script", lambda: session.create_script(agent_path.read_text(encoding="utf-8")), timeout)
    script.on("message", on_message)
    run_with_timeout("frida.script.load", script.load, timeout)
    return session, script


def controlled_restart_wechat(pid: int) -> int:
    print(
        f"[清理] 图片 callback 仍可能经过 Frida trampoline；正在受控重启 WeChat PID {pid}，"
        "避免 unload 竞态和下次注入失败。",
        flush=True,
    )
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 8.0
    while pid_alive(pid) and time.time() < deadline:
        time.sleep(0.2)
    if pid_alive(pid):
        print(f"[清理] WeChat PID {pid} 未在 8 秒内退出，执行强制终止。", flush=True)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.time() + 3.0
        while pid_alive(pid) and time.time() < deadline:
            time.sleep(0.1)

    subprocess.run(["open", "-a", "WeChat"], check=False)
    deadline = time.time() + 30.0
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            new_pid = find_wechat_pid()
            if new_pid != pid:
                print(f"[清理] WeChat 已受控重启：old_pid={pid} new_pid={new_pid}。", flush=True)
                return new_pid
        except Exception as exc:  # noqa: BLE001 - process startup is asynchronous
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"受控重启后 30 秒内未发现新的 WeChat 主进程：{last_error}")


def build_upload_payload_img() -> bytes:
    payload = bytes.fromhex(UPLOAD_IMG_PAYLOAD_HEX)
    if len(payload) != 0x2F8:
        raise RuntimeError(f"bad upload payload len: {len(payload)}")
    return payload


def build_send_payload_img(task_id: int) -> bytes:
    payload_data = bytearray([
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0xEC, 0x0E, 0x12, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA,
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D,
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B,
        0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10,
    ])
    payload_data.extend(b"\x00" * (412 - len(payload_data)))
    payload_data[0] = 0x6E
    payload_data[16] = 0x10
    payload_data[28] = 0x22
    payload_data[92] = 0x6E
    payload = bytearray(0x1A0)
    payload[0:4] = int(task_id).to_bytes(4, "little", signed=False)
    payload[4:] = payload_data
    return bytes(payload)


def wx_string(value: str) -> bytes:
    return field_bytes(1, value.encode("utf-8"))


def field_zero_varint(number: int) -> bytes:
    return encode_varint((number << 3) | 0) + b"\x00"


def random_client_proof() -> bytes:
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    return ("m64" + "".join(random.choice(chars) for _ in range(13))).encode("ascii")


def build_img_proto(sender: str, target_id: str, cdn_key: str, aes_key: str, md5_key: str) -> bytes:
    ts = int(time.time())
    client_msg_id = f"{target_id}_{ts}_160_xwechat_3"
    session_id = random.randrange(100000000, 4100000000)
    device_id = random.getrandbits(64) | (0xFFFFFFFF << 32)
    header = b"".join([
        field_bytes(1, b"\x00"),
        field_varint(2, session_id),
        field_bytes(3, random_client_proof()),
        field_varint(4, device_id),
        field_bytes(5, b"UnifiedPCMac 26 arm64"),
        field_varint(6, 304),
    ])
    xml = b"<msgsource><alnode><fr>1</fr></alnode></msgsource>"
    cdn = cdn_key.encode("utf-8")
    aes = aes_key.encode("utf-8")
    md5 = md5_key.encode("utf-8")
    data = b"".join([
        field_bytes(1, header),
        field_bytes(2, wx_string(client_msg_id)),
        field_bytes(3, wx_string(sender)),
        field_bytes(4, wx_string(target_id)),
        field_varint(5, 1524),
        field_varint(7, 1524),
        field_varint(9, 3),
        field_bytes(10, xml),
        field_varint(11, 1),
        field_varint(12, 2),
        field_bytes(15, cdn),
        field_bytes(16, cdn),
        field_bytes(17, aes),
        field_varint(18, 1),
        field_varint(19, 2559),
        field_varint(20, 2559),
        field_bytes(21, cdn),
        field_varint(22, 1524),
        field_varint(23, 104),
        field_varint(24, 58),
        field_bytes(25, aes),
        field_bytes(27, md5),
        field_varint(28, 779219929),
    ])
    data += field_zero_varint(6)
    data += bytes([0x42, 0x04, 0x08, 0x00, 0x12, 0x00])
    data += field_zero_varint(13)
    data += field_zero_varint(30)
    data += field_zero_varint(36)
    data += field_zero_varint(41)
    data += b"\x00"
    return data


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="通过同一 Frida 原生链路连续发送文本和图片消息。")
    ap.add_argument("--message-type", choices=("text", "image"), default="image")
    ap.add_argument("--receiver", default="filehelper")
    ap.add_argument("--message", default="", help="初始文本消息；message-type=text 时必填")
    ap.add_argument("--at-user", default="", help="初始文本的 @ 用户 wxid")
    ap.add_argument("--sender", help="当前登录 wxid；默认从 xwechat_files 目录推断")
    ap.add_argument("--image", type=Path, help="图片路径；默认生成一张测试 PNG")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--task-id", type=int, default=0x20000091)
    ap.add_argument("--timeout", type=float, default=40.0)
    ap.add_argument("--context-timeout", type=float, default=120.0)
    ap.add_argument("--attach-timeout", type=float, default=20.0, help="Frida attach/create/load 单步超时秒数，避免 TUI 卡在重注入。")
    ap.add_argument("--controlled-restart-on-attach-timeout", action="store_true", help="attach 超时后受控重启 WeChat 并重试一次。")
    ap.add_argument("--upload-timeout", type=float, default=90.0)
    ap.add_argument(
        "--upload-readiness-seconds",
        type=float,
        default=180.0,
        help="微信刚启动时，上传入口返回 -20001 的最长就绪等待窗口；期间每 15 秒重试。-20003 属于参数/路径校验失败，不在同一 PID 内盲目重试。",
    )
    ap.add_argument(
        "--post-finish-hold",
        type=float,
        default=5.0,
        help="图片对象复用或最终释放前，距最后一次 ack 的最小安全窗口。",
    )
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--attach-smoke", action="store_true")
    ap.add_argument(
        "--learn-callbacks-only",
        action="store_true",
        help="只等待手动图片上传并动态捕获 callback 方法；不触发实验上传/发送。",
    )
    ap.add_argument(
        "--learn-lifecycle-only",
        action="store_true",
        help="只等待手动图片上传并捕获真实 upload x1 / image send object 生命周期模板；不触发实验上传/发送。",
    )
    ap.add_argument(
        "--use-real-lifecycle-template",
        action="store_true",
        help="实验上传/发送时使用手动图片捕获的真实 upload x1 与 image send object 模板进行 clone。",
    )
    ap.add_argument(
        "--use-static-image-callback-profile",
        action="store_true",
        help="强制使用 profile 里的静态图片 callback 方法 offset；像文本 hook 一样按 module.base + offset 计算，不做 hash gate。",
    )
    ap.add_argument(
        "--proactive-upload-wrapper",
        action="store_true",
        help="主动调用图片上传入口 wrapper（module.base+0x525a008），不再等待用户手动发图捕获 upload x0。",
    )
    ap.add_argument("--i-accept-freeze-risk", action="store_true")
    ap.add_argument(
        "--i-accept-image-known-freeze-risk",
        action="store_true",
        help="图片真实上传/发送已多次复现 WeChat 高 CPU/事件源递归假死；仅用于复现或验证修复。",
    )
    ap.add_argument(
        "--i-accept-image-lifecycle-whitepage-risk",
        action="store_true",
        help="生命周期 clone 真发已复现闪退/白屏/100%% CPU；默认阻断，仅保留给崩溃复现。",
    )
    ap.add_argument(
        "--i-accept-image-callback-crash-risk",
        action="store_true",
        help="图片上传 callback wrapper 适配尚未完成，已观察到 WeChat 闪退；必须显式确认才允许继续真实图片上传。",
    )
    ap.add_argument("--keep-frida-helper", action="store_true")
    ap.add_argument(
        "--unsafe-agent-auto-detach-hooks",
        action="store_true",
        help="恢复旧行为：agent 在 upload_finish/ack 后立刻拆 hook。已观察到延迟闪退，仅用于复现。",
    )
    ap.add_argument(
        "--cleanup-timeout",
        type=float,
        default=30.0,
        help="等待 force_cleanup/unload/detach 完成的秒数；真发图片后 3 秒太短，容易把 helper 砍在半路。",
    )
    ap.add_argument(
        "--cleanup-mode",
        choices=("detach-only", "unload-detach"),
        default="unload-detach",
        help=(
            "Frida 释放方式。unload-detach=标准顺序，先卸载脚本再分离会话；"
            "detach-only=仅用于对比调试，可能让当前 WeChat 注入状态变脏。"
        ),
    )
    ap.add_argument("--health-check-seconds", type=float, default=12.0)
    ap.add_argument(
        "--manual-release-file",
        type=Path,
        help="成功后保持 hooks/session，直到该文件出现才执行清理。",
    )
    ap.add_argument(
        "--command-dir",
        type=Path,
        help="常驻 session 的连续发送命令目录。",
    )
    ap.add_argument(
        "--controlled-restart-on-release",
        action="store_true",
        help="图片真实执行最终释放时受控重启微信，避免 callback trampoline 卸载竞态和脏进程残留。",
    )
    ap.add_argument("--output", type=Path, default=Path("/tmp/wechat-native-send-image-once.jsonl"))
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    sender, account_dir = detect_account_dir(args.sender)
    if not sender:
        raise RuntimeError("缺少 sender wxid")
    marker = f"CHATLOG-NATIVE-IMAGE-RETEST-{int(time.time())}"
    staged_image_paths: dict[Path, float | None] = {}

    def cleanup_staged_images(force: bool = False) -> None:
        now = time.monotonic()
        for staged_path, retired_at in list(staged_image_paths.items()):
            if not force and (retired_at is None or now - retired_at < args.post_finish_hold):
                continue
            staged_path.unlink(missing_ok=True)
            staged_image_paths.pop(staged_path, None)

    def retire_staged_image(staged_path: Path) -> None:
        if staged_path in staged_image_paths:
            staged_image_paths[staged_path] = time.monotonic()

    atexit.register(cleanup_staged_images, True)

    initial_is_image = args.message_type == "image"
    if not initial_is_image and args.execute and not args.message:
        raise RuntimeError("message-type=text 时缺少 --message")
    generated_image = initial_is_image and args.image is None
    image_path = args.image
    if initial_is_image and image_path is None:
        image_path = account_dir / "temp/chatlog_alpha/Img" / f"{marker}.png"
        make_test_png(image_path, marker)
    if image_path is not None:
        image_path = image_path.expanduser().resolve()
    if generated_image and image_path is not None:
        staged_image_paths[image_path] = None
    if initial_is_image and args.execute and image_path is not None:
        image_path, staged = stage_image_in_wechat_container(image_path, account_dir, marker)
        if staged:
            staged_image_paths[image_path] = None
    md5 = file_md5(image_path) if image_path is not None else ""
    upload_payload = build_upload_payload_img() if initial_is_image else b""
    send_payload = build_send_payload_img(args.task_id) if initial_is_image else build_send_payload_text(args.task_id)

    progress(1, 8, "准备混合图文 Session 与初始消息 payload")
    if initial_is_image:
        print(f"      type=image sender={sender!r} receiver={args.receiver!r} image={image_path} md5={md5} upload_len={len(upload_payload)} send_len={len(send_payload)}", flush=True)
    else:
        print(f"      type=text sender={sender!r} receiver={args.receiver!r} message_len={len(args.message.encode('utf-8'))} send_len={len(send_payload)}", flush=True)
    if initial_is_image and args.execute and image_path is not None:
        print(
            f"      图片已放入微信容器目录：{image_path} "
            f"(path_bytes={len(str(image_path).encode('utf-8'))}/{MAX_WECHAT_UPLOAD_PATH_BYTES}，"
            "私有副本已写入去重盐)",
            flush=True,
        )

    if not args.execute and not args.attach_smoke and not args.learn_callbacks_only and not args.learn_lifecycle_only:
        print("DRY RUN：没有 attach WeChat，也没有上传/发送。图片真实执行需 --execute --i-accept-freeze-risk。", flush=True)
        return 0
    if args.execute and not args.i_accept_freeze_risk:
        raise RuntimeError("安全拦截：图片 native 测试仍是实验路径；真实执行需显式加 --i-accept-freeze-risk。")
    if args.execute and not args.i_accept_image_known_freeze_risk:
        raise RuntimeError(
            "安全拦截：图片真实上传/发送已多次复现 WeChat 高 CPU/事件源递归假死；"
            "当前仅允许 attach-smoke / learn-callbacks-only / learn-lifecycle-only。"
            "若要继续复现或验证修复，需额外加 --i-accept-image-known-freeze-risk。"
        )
    if args.execute and args.use_real_lifecycle_template and not args.i_accept_image_lifecycle_whitepage_risk:
        raise RuntimeError(
            "安全拦截：--use-real-lifecycle-template 真发复测已复现 WeChat 闪退与消息页白屏/100% CPU；"
            "当前只建议 --learn-lifecycle-only。若只是复现崩溃，需额外加 --i-accept-image-lifecycle-whitepage-risk。"
        )
    if args.use_static_image_callback_profile:
        print("静态图片 callback profile 已启用：按 module.base + profile offset 强制使用 callback。", flush=True)
    if args.execute and args.i_accept_image_callback_crash_risk:
        print(
            "高危模式：允许使用静态图片 callback fallback；该路径已触发过 WeChat 闪退，仅用于崩溃复现。",
            file=sys.stderr,
            flush=True,
        )

    try:
        import frida
    except ModuleNotFoundError as exc:
        raise RuntimeError("缺少 Python frida 模块；执行 python3 -m pip install --user frida") from exc

    upload_done = threading.Event()
    upload_attempted = threading.Event()
    send_finished = threading.Event()
    finish_timed_out = threading.Event()
    failed = threading.Event()
    upload_info: dict[str, str] = {}
    upload_results: dict[str, dict[str, str]] = {}
    upload_results_changed = threading.Condition()
    args.output.unlink(missing_ok=True)

    def wait_for_upload_result(file_id: str, timeout: float) -> dict[str, str] | None:
        deadline = time.monotonic() + timeout
        with upload_results_changed:
            while file_id not in upload_results:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                upload_results_changed.wait(remaining)
            return upload_results.pop(file_id)

    def save(payload_obj: dict[str, object]) -> None:
        row = {"ts": time.time(), **payload_obj}
        if args.output.exists() and args.output.stat().st_size >= MAX_EVENT_LOG_BYTES:
            rotated = Path(f"{args.output}.1")
            rotated.unlink(missing_ok=True)
            args.output.replace(rotated)
        with args.output.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        if message.get("type") == "error":
            print(f"[Frida] {message.get('stack', message)}", file=sys.stderr, flush=True)
            failed.set()
            return
        payload_obj = message.get("payload")
        if not isinstance(payload_obj, dict):
            return
        save(payload_obj)
        typ = payload_obj.get("type")
        if typ == "context_captured":
            print(f"[事件] 已捕获 StartTask x0={payload_obj.get('x0')}", flush=True)
        elif typ == "upload_context_captured":
            print(f"[事件] 已捕获 upload x0={payload_obj.get('x0')}", flush=True)
        elif typ == "upload_callback_method_captured":
            print(
                f"[事件] 已动态捕获图片 callback 方法：{payload_obj.get('slot')} -> {payload_obj.get('func')}",
                flush=True,
            )
        elif typ == "upload_lifecycle_template_captured":
            ptr_fields = payload_obj.get("ptr_fields") if isinstance(payload_obj.get("ptr_fields"), dict) else {}
            print(
                f"[事件] 已捕获真实 upload x1 生命周期模板：x1={payload_obj.get('x1')} "
                f"func1_cloneable={payload_obj.get('func1_cloneable')} func2_cloneable={payload_obj.get('func2_cloneable')} "
                f"file_id_ptr={ptr_fields.get('0x48')}",
                flush=True,
            )
        elif typ == "upload_callback_lifecycle_template_captured":
            print(
                f"[事件] 已捕获真实 upload callback dispatch 表：table={payload_obj.get('table')} "
                f"get={payload_obj.get('get_callback_slot')} on_complete={payload_obj.get('on_complete_slot')}",
                flush=True,
            )
        elif typ == "upload_callback_lifecycle_template_applied":
            print(
                f"[事件] 已克隆真实 upload callback dispatch 表：clone={payload_obj.get('clone_table')}",
                flush=True,
            )
        elif typ == "image_send_lifecycle_template_captured":
            print(
                f"[事件] 已捕获真实 image send object 模板：send={payload_obj.get('send_object')} "
                f"msg={payload_obj.get('message_object')} cgi={payload_obj.get('cgi')} task={payload_obj.get('task_id')}",
                flush=True,
            )
        elif typ == "upload_triggering":
            file_id_note = ""
            if payload_obj.get("file_id_receiver_truncated"):
                file_id_note = "（群聊 receiver 前缀已按 38-byte profile 安全截短）"
            print(
                f"[事件] 开始上传图片 file_id={payload_obj.get('file_id')} "
                f"len={payload_obj.get('file_id_length')}{file_id_note} "
                f"receiver={payload_obj.get('receiver_string_mode')}/"
                f"{payload_obj.get('receiver_utf8_length')}B "
                f"path={payload_obj.get('path_utf8_length')}B",
                flush=True,
            )
        elif typ == "upload_trigger_returned":
            print(
                f"[事件] 上传函数已返回 rv={payload_obj.get('return_value')} "
                f"signed32={payload_obj.get('return_value_signed32')}",
                flush=True,
            )
        elif typ == "upload_trigger_rejected":
            signed32 = payload_obj.get("return_value_signed32")
            if signed32 == -20001:
                hint = "微信图片上传服务尚未初始化；请确认已登录，并打开微信主窗口或文件传输助手后重试"
            elif signed32 == -20003:
                hint = (
                    "微信拒绝了 synthetic upload 参数或文件路径；"
                    f"当前实现会把暂存绝对路径限制在 {MAX_WECHAT_UPLOAD_PATH_BYTES} UTF-8 bytes 内，"
                    "不要在同一 PID 内盲目等待"
                )
            else:
                hint = "请按返回码检查上传服务状态和 synthetic upload 对象"
            print(
                f"[事件] 微信上传入口拒绝请求：rv={payload_obj.get('return_value')} "
                f"signed32={signed32} file_id={payload_obj.get('file_id')} "
                f"path={payload_obj.get('path')}；{hint}",
                file=sys.stderr,
                flush=True,
            )
        elif typ == "upload_preflight_probe":
            check = payload_obj.get("check")
            if check == "manager_rsa":
                print(
                    "[诊断] 上传 manager RSA preflight："
                    f"result={payload_obj.get('result')} "
                    f"b8_len={(payload_obj.get('rsa_b8') or {}).get('length')} "
                    f"d0_len={(payload_obj.get('rsa_d0') or {}).get('length')} "
                    f"e8_len={(payload_obj.get('rsa_e8') or {}).get('length')}",
                    flush=True,
                )
            else:
                image_path_info = payload_obj.get("image_path") or {}
                print(
                    "[诊断] 上传 request/path preflight："
                    f"result={payload_obj.get('result')} "
                    f"path_len={image_path_info.get('length')} field_1e0={payload_obj.get('field_1e0')}",
                    flush=True,
                )
        elif typ == "image_generation_acquired":
            action = "复用安全池对象" if payload_obj.get("reused") else "创建独立对象"
            print(
                f"[事件] 图片 generation {payload_obj.get('generation_id')}：{action}；"
                f"pool={payload_obj.get('pool_size')} retention={payload_obj.get('retention_ms')}ms",
                flush=True,
            )
        elif typ == "image_generation_retired":
            print(
                f"[事件] 图片 generation {payload_obj.get('generation_id')} 已进入延迟复用池，"
                f"reason={payload_obj.get('reason')}",
                flush=True,
            )
        elif typ == "upload_callback_wrapper_patched":
            print(f"[事件] 已接管图片 GetCallback wrapper dynamic={payload_obj.get('dynamic')} static={payload_obj.get('static_profile')}", flush=True)
        elif typ == "upload_oncomplete_patched":
            print(f"[事件] 已接管图片 OnComplete wrapper dynamic={payload_obj.get('dynamic')} static={payload_obj.get('static_profile')}", flush=True)
        elif typ == "upload_callback_wrapper_bypassed":
            print(
                f"[事件] 生命周期模板模式：保留原始 GetCallback x8，不覆盖 callback 表 x8={payload_obj.get('x8')}",
                flush=True,
            )
        elif typ == "upload_oncomplete_bypassed":
            print(
                f"[事件] 生命周期模板模式：保留原始 OnComplete x8，不覆盖 callback 表 x8={payload_obj.get('x8')}",
                flush=True,
            )
        elif typ in {"upload_callback_wrapper_blocked", "upload_oncomplete_blocked"}:
            print(f"[事件] {typ}: {payload_obj}", file=sys.stderr, flush=True)
            failed.set()
        elif typ == "upload_image_incomplete":
            print(
                "[事件] 图片上传回调不完整："
                f"generation={payload_obj.get('generation_id')} "
                f"cdn_len={payload_obj.get('cdn_key_length')} aes_len={payload_obj.get('aes_key_length')}；"
                "未使用本次请求 AES 冒充旧 CDN 密钥，继续等待完整回调。",
                file=sys.stderr,
                flush=True,
            )
        elif typ == "upload_image_finish":
            finished_info = {
                "cdn_key": str(payload_obj.get("cdn_key") or ""),
                "aes_key": str(payload_obj.get("aes_key") or ""),
                "md5_key": str(payload_obj.get("md5_key") or ""),
            }
            upload_info.update(finished_info)
            file_id = str(payload_obj.get("file_id") or "")
            with upload_results_changed:
                upload_results[file_id] = finished_info
                while len(upload_results) > 256:
                    upload_results.pop(next(iter(upload_results)))
                upload_results_changed.notify_all()
            print(
                f"[事件] 图片上传完成 generation={payload_obj.get('generation_id')} "
                f"cdn_len={len(finished_info['cdn_key'])} aes_len={len(finished_info['aes_key'])} "
                f"aes_source={payload_obj.get('aes_key_source') or 'callback'}",
                flush=True,
            )
            upload_done.set()
        elif typ == "cleanup_policy_configured":
            print(
                "[事件] 清理策略已设置："
                f"{payload_obj.get('model')} "
                f"auto_ack={payload_obj.get('auto_detach_hooks_after_ack')} "
                f"auto_upload={payload_obj.get('auto_detach_upload_hooks_after_finish')}",
                flush=True,
            )
        elif typ == "upload_hooks_retained":
            print(
                f"[事件] 图片上传 hooks 暂不拆除，等待 drain 后统一释放；count={payload_obj.get('upload_hook_count')}",
                flush=True,
            )
        elif typ == "hooks_retained_after_finish":
            print(
                f"[事件] 发送完成后 hooks 暂不拆除，等待 drain 后统一释放；upload_hooks={payload_obj.get('upload_hook_count')}",
                flush=True,
            )
        elif typ == "triggering":
            print(
                f"[事件] 开始发送图片 task_id={payload_obj.get('task_id')} "
                f"dispatch={payload_obj.get('dispatch_mode')}",
                flush=True,
            )
        elif typ == "req2buf_inserted":
            print(f"[事件] Req2Buf 已挂入 fake image object：{payload_obj.get('address')}", flush=True)
        elif typ == "protobuf_written":
            print(f"[事件] 图片 protobuf 已写入 AutoBuffer，len={payload_obj.get('length')}", flush=True)
        elif typ == "buf2resp_ack":
            print(f"[事件] 图片 Buf2Resp ack 已匹配，len={payload_obj.get('response_len')}", flush=True)
        elif typ in {"insert_cleanup", "finish", "finish_timeout_cleanup"}:
            strategy = payload_obj.get("strategy")
            suffix = f" strategy={strategy}" if strategy else ""
            print(f"[事件] {typ}：资源已清理{suffix}", flush=True)
            if typ == "finish_timeout_cleanup":
                finish_timed_out.set()
            if typ in {"finish", "finish_timeout_cleanup"}:
                send_finished.set()
        elif typ == "hooks_detached":
            print(f"[事件] Frida hooks 已主动拆除 reason={payload_obj.get('reason')}", flush=True)
        elif typ == "upload_hooks_detached":
            print(f"[事件] 图片上传 hooks 已拆除 reason={payload_obj.get('reason')} names={payload_obj.get('names')}", flush=True)
        elif str(typ).endswith("error"):
            print(f"[事件] {typ}: {payload_obj}", file=sys.stderr, flush=True)
            failed.set()

    pid = args.pid or find_wechat_pid()
    progress(2, 8, f"连接 WeChat 主进程 PID {pid}")
    session = None
    script = None
    max_attach_attempts = 2 if args.controlled_restart_on_attach_timeout else 1
    for attach_attempt in range(1, max_attach_attempts + 1):
        try:
            session, script = attach_and_load_agent(frida, pid, AGENT, on_message, args.attach_timeout)
            break
        except AttachTimeoutError as exc:
            print(f"[attach] {exc}；当前 WeChat PID 可能存在脏注入状态。", file=sys.stderr, flush=True)
            shutdown_frida_runtime(frida, 3.0)
            if not args.keep_frida_helper:
                cleanup_frida_helpers()
            if args.controlled_restart_on_attach_timeout and attach_attempt == 1:
                pid = controlled_restart_wechat(pid)
                progress(2, 8, f"重试连接 WeChat 主进程 PID {pid}")
                continue
            raise
        except Exception:
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    pass
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
            shutdown_frida_runtime(frida, 10.0)
            if not args.keep_frida_helper:
                cleanup_frida_helpers()
            raise
    else:
        raise RuntimeError("Frida attach 未完成")

    try:
        cleanup_policy = script.exports_sync.configure_cleanup(
            bool(args.unsafe_agent_auto_detach_hooks),
            bool(args.unsafe_agent_auto_detach_hooks),
        )
        save({"type": "cleanup_policy", "policy": cleanup_policy})
        retention_policy = script.exports_sync.configure_generation_retention(args.post_finish_hold)
        if not retention_policy.get("ok"):
            raise RuntimeError(f"配置图片 generation 安全窗口失败: {retention_policy}")
        save({"type": "image_generation_retention", "policy": retention_policy})
        details = script.exports_sync.inspect()
        save({"type": "agent_ready", "details": details})
        progress(3, 8, "图片 hooks 已安装，检查 hook 指令")
        h = details["hook_details"]
        print(
            f"      send={h['sendFuncAddr']} upload={h['uploadImageAddr']} "
            f"start_default={h.get('defaultStartTaskFuncAddr')} upload_entry={h.get('uploadImageEntryWrapperAddr')} "
            f"cdn={h['cndOnCompleteAddr']} ack={h['buf2RespAckHookAddr']}",
            flush=True,
        )

        last_finish_at = [0.0]

        def mark_finish() -> None:
            last_finish_at[0] = time.monotonic()

        def wait_image_lifecycle(reason: str) -> None:
            if last_finish_at[0] <= 0 or args.post_finish_hold <= 0:
                return
            elapsed = time.monotonic() - last_finish_at[0]
            remaining = max(0.0, args.post_finish_hold - elapsed)
            if remaining > 0:
                print(
                    f"[最终排空] 图片 upload object 仍在安全窗口内；{reason}前等待 {remaining:.1f} 秒。",
                    flush=True,
                )
                time.sleep(remaining)

        def final_image_drain() -> None:
            wait_image_lifecycle("释放")
            cleanup_staged_images(force=True)

        def trigger_upload_when_ready(
            receiver: str,
            image_md5: str,
            upload_image: Path,
            payload: bytes,
            result_type: str,
            command_id: object = None,
        ) -> dict[str, object]:
            upload_attempted.set()
            attempt = 0
            while True:
                attempt += 1
                result = script.exports_sync.trigger_upload_image(
                    receiver,
                    image_md5,
                    str(upload_image),
                    payload.hex(),
                    bool(args.i_accept_image_callback_crash_risk or args.use_static_image_callback_profile),
                    bool(args.use_real_lifecycle_template),
                    bool(args.use_static_image_callback_profile),
                    bool(args.proactive_upload_wrapper),
                )
                save({
                    "type": result_type,
                    "command_id": command_id,
                    "attempt": attempt,
                    "result": result,
                })
                if result.get("ok"):
                    if attempt > 1:
                        print(f"[就绪] 微信上传服务已恢复，attempt={attempt} rv=0。", flush=True)
                    return result

                signed32 = result.get("return_value_signed32")
                if not args.proactive_upload_wrapper or signed32 != -20001:
                    return result

                uptime = process_uptime_seconds(pid)
                if uptime is not None:
                    remaining = args.upload_readiness_seconds - uptime
                else:
                    remaining = args.upload_readiness_seconds - (attempt - 1) * 15.0
                if remaining <= 0:
                    print(
                        f"[就绪] 微信上传服务在 {args.upload_readiness_seconds:.0f} 秒启动窗口后仍返回 {signed32}；"
                        "交给受控重启兜底。",
                        flush=True,
                    )
                    return result

                delay = min(15.0, remaining)
                uptime_text = "未知" if uptime is None else f"{uptime:.0f} 秒"
                print(
                    f"[就绪] 微信进程运行 {uptime_text}，上传服务尚未完成初始化({signed32})；"
                    f"{delay:.0f} 秒后自动重试 attempt={attempt + 1}。",
                    flush=True,
                )
                time.sleep(delay)

        def execute_persistent_command(command: dict[str, object]) -> None:
            command_receiver = str(command.get("receiver") or "").strip()
            command_sender = str(command.get("sender") or sender).strip()
            sequence = int(command.get("sequence") or 0)
            task_id = (args.task_id + max(1, sequence)) & 0xFFFFFFFF
            message_type = str(command.get("message_type") or "image").strip().lower()
            if message_type == "text":
                command_content = str(command.get("content") or "")
                command_at_user = str(command.get("at_user") or "").strip()
                if not command_receiver or not command_content:
                    raise RuntimeError("连续文本发送缺少 receiver 或 content")
                print(
                    f"[命令:{command.get('command_id') or sequence}] 混合队列路由=text "
                    f"receiver={command_receiver!r} content_bytes={len(command_content.encode('utf-8'))}",
                    flush=True,
                )
                send_finished.clear()
                finish_timed_out.clear()
                failed.clear()
                command_proto = build_text_proto(command_receiver, command_content, command_at_user)
                command_payload = build_send_payload_text(task_id)
                result = script.exports_sync.trigger_send_text(
                    task_id,
                    command_proto.hex(),
                    command_payload.hex(),
                )
                save({"type": "persistent_text_send_result", "command_id": command.get("command_id"), "result": result})
                if not result.get("ok"):
                    raise RuntimeError(f"连续文本发送 trigger 失败: {result}")
                if not send_finished.wait(args.timeout):
                    status = script.exports_sync.status()
                    raise RuntimeError(f"连续文本发送等待 finish 超时: {status}")
                if finish_timed_out.is_set():
                    raise RuntimeError("连续文本发送未收到 Buf2Resp ack，已由 Agent 超时清理")
                if failed.is_set():
                    raise RuntimeError("连续文本发送收到 Frida 错误事件")
                mark_finish()
                return
            if message_type != "image":
                raise RuntimeError(f"未知连续消息类型: {message_type}")

            command_image = Path(str(command.get("image_path") or "")).expanduser().resolve()
            if not command_receiver or not command_sender or not command_image.is_file():
                raise RuntimeError("连续图片发送缺少 receiver、sender 或有效图片")

            cleanup_staged_images()
            command_marker = f"{marker}-command-{command.get('command_id') or sequence}"
            command_image, command_staged = stage_image_in_wechat_container(
                command_image,
                account_dir,
                command_marker,
            )
            if command_staged:
                staged_image_paths[command_image] = None
            print(
                f"[命令:{command.get('command_id') or sequence}] 图片已放入微信容器目录：{command_image} "
                f"(path_bytes={len(str(command_image).encode('utf-8'))}/{MAX_WECHAT_UPLOAD_PATH_BYTES}，"
                "私有副本已写入去重盐)",
                flush=True,
            )

            # Each command gets its own native generation. Previous objects stay
            # untouched in the delayed-callback retention pool, so the queue can
            # start the next image immediately after the current ack.
            upload_done.clear()
            send_finished.clear()
            finish_timed_out.clear()
            failed.clear()
            command_md5 = file_md5(command_image)
            command_upload_payload = build_upload_payload_img()
            result = trigger_upload_when_ready(
                command_receiver,
                command_md5,
                command_image,
                command_upload_payload,
                "persistent_upload_result",
                command.get("command_id"),
            )
            if not result.get("ok"):
                signed32 = result.get("return_value_signed32")
                if signed32 == -20003:
                    raise RuntimeError(
                        "微信拒绝图片上传参数或文件路径(-20003)；"
                        f"path_bytes={len(str(command_image).encode('utf-8'))}/"
                        f"{MAX_WECHAT_UPLOAD_PATH_BYTES} path={command_image} result={result}"
                    )
                raise RuntimeError(f"连续图片上传 trigger 失败: {result}")
            command_file_id = str(result.get("file_id") or "")
            command_upload_info = wait_for_upload_result(command_file_id, args.upload_timeout)
            if command_upload_info is None:
                raise RuntimeError(f"连续图片发送等待 upload_image_finish 超时: file_id={command_file_id}")
            if not command_upload_info.get("cdn_key") or not command_upload_info.get("aes_key"):
                raise RuntimeError(f"连续图片上传回调缺少 cdn/aes: {command_upload_info}")

            command_proto = build_img_proto(
                command_sender,
                command_receiver,
                command_upload_info["cdn_key"],
                command_upload_info["aes_key"],
                command_upload_info.get("md5_key") or command_md5,
            )
            command_payload = build_send_payload_img(task_id)
            result = script.exports_sync.trigger_send_image(
                task_id,
                command_sender,
                command_receiver,
                command_proto.hex(),
                command_payload.hex(),
                bool(args.use_real_lifecycle_template),
            )
            save({"type": "persistent_send_result", "command_id": command.get("command_id"), "result": result})
            if not result.get("ok"):
                raise RuntimeError(f"连续图片发送 trigger 失败: {result}")
            if not send_finished.wait(args.timeout):
                status = script.exports_sync.status()
                script.exports_sync.force_cleanup()
                raise RuntimeError(f"连续图片发送等待 finish 超时: {status}")
            if finish_timed_out.is_set():
                raise RuntimeError("连续图片发送未收到 Buf2Resp ack，已由 Agent 超时清理")
            if failed.is_set():
                raise RuntimeError("连续图片发送收到 Frida 错误事件")
            mark_finish()
            retire_staged_image(command_image)

        if args.unsafe_agent_auto_detach_hooks:
            print("      ⚠️ 旧清理策略：agent 会在回调后立刻拆 hook，可能复现延迟闪退。", flush=True)
        else:
            print(
                f"      安全生命周期：每张图片使用独立 generation；upload/ack 后保留 hooks，最终释放前确保距最后 ack {args.post_finish_hold:.0f} 秒。",
                flush=True,
            )
        if args.attach_smoke and not args.execute and not args.learn_callbacks_only and not args.learn_lifecycle_only:
            print("ATTACH SMOKE：图片 hooks 已加载并完成 inspect；不上传、不发送。", flush=True)
            wait_for_manual_release(args.manual_release_file, args.command_dir, execute_persistent_command, final_image_drain)
            return 0

        if args.proactive_upload_wrapper:
            if initial_is_image:
                progress(4, 8, "主动上传模式：不等手动发图，直接使用图片上传入口 wrapper")
            else:
                progress(4, 8, "混合 Session 已就绪：文本直发，后续图片使用主动上传 wrapper")
            print(
                "      使用 module.base+0x525a008 获取 WeChat 内部上传服务；"
                "发送阶段使用 module.base+0x51173b0 自动取得默认 MMSTN manager；"
                "不再依赖碰巧捕获其他 StartTask 流量。",
                flush=True,
            )
            if args.use_real_lifecycle_template:
                raise RuntimeError("--proactive-upload-wrapper 不能搭配 --use-real-lifecycle-template；该模式不依赖手动生命周期模板。")
            st = script.exports_sync.status()
            callback_ready = bool(st.get("callback_methods_ready"))
            if args.use_static_image_callback_profile or args.i_accept_image_callback_crash_risk:
                callback_ready = True
            if not callback_ready:
                raise RuntimeError(
                    "主动上传模式需要 callback 方法已知；请加 --use-static-image-callback-profile，"
                    "或先执行 learn-callbacks-only 动态学习。"
                )
        else:
            progress(4, 8, "等待 StartTask/upload 上下文，并动态学习图片 callback/生命周期模板")
            print("      请手动向文件传输助手发送任意一张小图片：用于捕获 upload x0、真实 callback、upload x1 模板、image send object 模板；本阶段只观察不改写。", flush=True)
            deadline = time.time() + args.context_timeout
            while time.time() < deadline:
                st = script.exports_sync.status()
                callback_ready = bool(st.get("callback_methods_ready"))
                if args.use_static_image_callback_profile:
                    callback_ready = True
                lifecycle_ready = True
                if args.learn_lifecycle_only or args.use_real_lifecycle_template:
                    lifecycle_ready = (
                        bool(st.get("upload_lifecycle_template_ready"))
                        and bool(st.get("upload_callback_lifecycle_template_ready"))
                        and bool(st.get("image_send_lifecycle_template_ready"))
                    )
                if args.i_accept_image_callback_crash_risk:
                    callback_ready = True
                if st.get("context_ready") and st.get("upload_context_ready") and callback_ready and lifecycle_ready:
                    break
                time.sleep(0.25)
            else:
                st = script.exports_sync.status()
                raise RuntimeError(f"等待上下文超时：{st}")

        if (args.learn_callbacks_only or args.learn_lifecycle_only) and not args.execute:
            st = script.exports_sync.status()
            print(
                "LEARN ONLY：已捕获上下文、callback/生命周期模板；未触发实验上传/发送。"
                f" get={st.get('learned_get_callback_func')} on_complete={st.get('learned_on_complete_func')} "
                f"upload_template={st.get('upload_lifecycle_template_ready')} "
                f"callback_template={st.get('upload_callback_lifecycle_template_ready')} "
                f"send_template={st.get('image_send_lifecycle_template_ready')}",
                flush=True,
            )
            wait_for_manual_release(args.manual_release_file, args.command_dir, execute_persistent_command, final_image_drain)
            return 0

        if not initial_is_image:
            progress(5, 8, "通过混合 Session 触发初始文本发送")
            send_finished.clear()
            finish_timed_out.clear()
            failed.clear()
            proto = build_text_proto(args.receiver, args.message, args.at_user)
            progress(6, 8, "构造文本 protobuf 并调用默认 MMSTN manager")
            result = script.exports_sync.trigger_send_text(args.task_id, proto.hex(), send_payload.hex())
            save({"type": "text_send_trigger_result", "result": result})
            if not result.get("ok"):
                raise RuntimeError(f"send text trigger failed: {result}")
            progress(7, 8, f"等待文本发送 ack 或超时 {args.timeout:.0f} 秒")
            if not send_finished.wait(args.timeout):
                st = script.exports_sync.status()
                save({"type": "timeout_status", "status": st})
                raise RuntimeError(f"文本发送未收到 finish: {st}")
            if failed.is_set() or finish_timed_out.is_set():
                return 4
            mark_finish()
            wait_for_manual_release(args.manual_release_file, args.command_dir, execute_persistent_command, final_image_drain)
            return 0

        progress(5, 8, "触发图片上传")
        result = trigger_upload_when_ready(
            args.receiver,
            md5,
            image_path,
            upload_payload,
            "upload_trigger_result",
        )
        if not result.get("ok"):
            if result.get("return_value_signed32") == -20003:
                raise RuntimeError(
                    "微信拒绝图片上传参数或文件路径(-20003)；"
                    f"path_bytes={len(str(image_path).encode('utf-8'))}/"
                    f"{MAX_WECHAT_UPLOAD_PATH_BYTES} path={image_path} result={result}"
                )
            raise RuntimeError(f"upload trigger failed: {result}")
        initial_file_id = str(result.get("file_id") or "")
        initial_upload_info = wait_for_upload_result(initial_file_id, args.upload_timeout)
        if initial_upload_info is None:
            raise RuntimeError(f"等待 upload_image_finish 超时: file_id={initial_file_id}")
        upload_info.clear()
        upload_info.update(initial_upload_info)
        if not upload_info.get("cdn_key") or not upload_info.get("aes_key"):
            raise RuntimeError(f"上传回调缺少 cdn/aes：{upload_info}")
        progress(6, 8, "构造图片 protobuf 并触发图片发送")
        proto = build_img_proto(sender, args.receiver, upload_info["cdn_key"], upload_info["aes_key"], upload_info.get("md5_key") or md5)
        print(f"      proto_len={len(proto)} cdn_len={len(upload_info['cdn_key'])} aes_len={len(upload_info['aes_key'])}", flush=True)
        result = script.exports_sync.trigger_send_image(
            args.task_id,
            sender,
            args.receiver,
            proto.hex(),
            send_payload.hex(),
            bool(args.use_real_lifecycle_template),
        )
        save({"type": "send_trigger_result", "result": result})
        if not result.get("ok"):
            raise RuntimeError(f"send image trigger failed: {result}")

        progress(7, 8, f"等待图片发送 ack 或超时 {args.timeout:.0f} 秒")
        if not send_finished.wait(args.timeout):
            st = script.exports_sync.status()
            save({"type": "timeout_status", "status": st})
            print(f"等待结束：未收到 finish，当前状态 {st}；执行强制清理。", file=sys.stderr, flush=True)
            script.exports_sync.force_cleanup()
            return 4
        if failed.is_set():
            return 2
        if finish_timed_out.is_set():
            return 4
        mark_finish()
        retire_staged_image(image_path)
        wait_for_manual_release(args.manual_release_file, args.command_dir, execute_persistent_command, final_image_drain)
        return 0
    finally:
        controlled_restart_pid = 0
        controlled_restart_error: Exception | None = None
        restart_replaced_process = False
        use_controlled_restart = bool(
            args.controlled_restart_on_release and args.execute and upload_attempted.is_set()
        )
        if use_controlled_restart:
            progress(8, 8, "安全释放图片 session：受控重启微信并清理 Frida helper")
            cleanup_staged_images(force=True)
            try:
                controlled_restart_pid = controlled_restart_wechat(pid)
                restart_replaced_process = controlled_restart_pid > 0 and not pid_alive(pid)
            except Exception as exc:  # noqa: BLE001 - helper cleanup must still run
                controlled_restart_error = exc
                restart_replaced_process = not pid_alive(pid)
                print(
                    f"[清理] WeChat 受控重启失败；若旧 PID 仍存活，将回退 force_cleanup/unload/detach：{exc}",
                    file=sys.stderr,
                    flush=True,
                )
        else:
            progress(8, 8, f"释放 Frida 资源：保活结束 -> force_cleanup -> {args.cleanup_mode}")

        def run_cleanup_step(name: str, fn, timeout: float) -> bool:
            done = threading.Event()
            errors: list[str] = []

            def runner() -> None:
                try:
                    fn()
                except Exception as exc:  # noqa: BLE001 - cleanup must keep going
                    errors.append(str(exc))
                finally:
                    done.set()

            threading.Thread(target=runner, daemon=True).start()
            if not done.wait(max(1.0, timeout)):
                print(f"[清理] {name} 超过 {timeout:.0f} 秒仍未返回。", flush=True)
                return False
            if errors:
                print(f"[清理] {name} 返回异常，继续兜底：{errors[-1]}", flush=True)
            else:
                print(f"[清理] {name} 完成。", flush=True)
            return True

        def force_cleanup() -> None:
            script.exports_sync.force_cleanup()

        hot_cleanup_required = not use_controlled_restart or not restart_replaced_process
        force_ok = True
        if hot_cleanup_required:
            force_ok = run_cleanup_step("agent force_cleanup", force_cleanup, min(8.0, args.cleanup_timeout))
            time.sleep(0.5)
        try:
            script.off("message", on_message)
        except Exception:
            pass

        detached_ok = restart_replaced_process
        if hot_cleanup_required:
            if args.cleanup_mode == "unload-detach":
                unload_ok = run_cleanup_step("script.unload", script.unload, min(15.0, args.cleanup_timeout))
                # Session.detach is still the official fallback when explicit
                # script unload fails; detaching the last session normally
                # unloads its non-eternalized scripts.
                detached_ok = run_cleanup_step("session.detach", session.detach, min(8.0, args.cleanup_timeout))
                force_ok = force_ok and unload_ok
            else:
                # Diagnostic only: detach without explicit script.unload may leave the
                # current WeChat process in a dirty state where the next attach blocks.
                detached_ok = run_cleanup_step("session.detach", session.detach, args.cleanup_timeout)

        runtime_shutdown_ok = shutdown_frida_runtime(frida, min(10.0, args.cleanup_timeout))
        if runtime_shutdown_ok and getattr(session, "is_detached", False):
            detached_ok = True

        if restart_replaced_process:
            print("图片 Frida session 已随旧微信进程退出；跳过高风险 script.unload。", flush=True)
        elif force_ok and detached_ok:
            print("Frida hooks 已拆除，session 已分离。", flush=True)
        else:
            print("Frida 常规清理未完全确认：进入 helper 兜底清理。", flush=True)
        if args.keep_frida_helper:
            print("Frida helper 兜底清理已跳过（--keep-frida-helper）。", flush=True)
        else:
            remaining = wait_frida_helpers_gone(5.0)
            if remaining:
                killed = cleanup_frida_helpers()
                print(f"Frida helper 兜底清理完成：等待后仍残留 {remaining} 个，清理 {killed} 个。", flush=True)
            else:
                print("Frida helper 已自然退出，无残留。", flush=True)
        watch_wechat_health(controlled_restart_pid or pid, args.health_check_seconds)
        print(f"事件日志：{args.output}", flush=True)
        if controlled_restart_error is not None:
            raise RuntimeError(f"图片 session 已停止，但 WeChat 受控重启未完成：{controlled_restart_error}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("图片发送测试已由用户结束。", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"图片发送测试失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
