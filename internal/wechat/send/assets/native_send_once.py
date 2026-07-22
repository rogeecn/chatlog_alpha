#!/usr/bin/env python3
"""单次 Frida native 文本发送测试器：attach -> 发送一次 -> 清理 -> detach。"""

from __future__ import annotations

import argparse
import builtins
import json
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from native_probe import find_wechat_pid

ROOT = Path(__file__).resolve().parent
AGENT = ROOT / "native/single_send_agent.js"
PROFILE = ROOT / "profiles/4.1.11.55-candidate.json"
MAX_EVENT_LOG_BYTES = 8 * 1024 * 1024
_PRINT_LOCK = threading.Lock()


def locked_print(*args, **kwargs) -> None:
    """Keep progress and Frida callback lines from being spliced together."""
    with _PRINT_LOCK:
        builtins.print(*args, **kwargs)


print = locked_print


def encode_varint(value: int) -> bytes:
    value = int(value)
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field_varint(number: int, value: int) -> bytes:
    return encode_varint((number << 3) | 0) + encode_varint(value)


def field_bytes(number: int, value: bytes) -> bytes:
    return encode_varint((number << 3) | 2) + encode_varint(len(value)) + value


def build_text_proto(receiver: str, content: str, at_user: str = "") -> bytes:
    xml = "<msgsource>"
    if at_user:
        xml += f"<atuserlist>{at_user}</atuserlist>"
    xml += "<alnode><fr>1</fr></alnode></msgsource>"

    wx_string = field_bytes(1, receiver.encode("utf-8"))
    body = b"".join(
        [
            field_bytes(1, wx_string),
            field_bytes(2, content.encode("utf-8")),
            field_varint(3, 1),
            field_varint(4, int(time.time())),
            field_varint(5, random.randrange(1 << 34, 1 << 35)),
            field_bytes(6, xml.encode("utf-8")),
        ]
    )
    return field_varint(1, 1) + field_bytes(2, body)


def build_send_payload(task_id: int, msg_type: str = "text") -> bytes:
    # 来自 upstream BuildSendPayload 的 text 模板；总长 0x1a0。
    payload_data = bytearray(
        [
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
        ]
    )
    payload_data.extend(b"\x00" * (412 - len(payload_data)))
    if len(payload_data) != 412:
        raise AssertionError(f"bad payload template size: {len(payload_data)}")

    if msg_type != "text":
        raise ValueError("only text is implemented in this standalone test")
    payload_data[0] = 0x0A
    payload_data[1] = 0x02
    payload_data[16] = 0x01
    payload_data[28] = 0x20
    payload_data[92] = 0x0A
    payload_data[93] = 0x02

    payload = bytearray(0x1A0)
    payload[0:4] = int(task_id).to_bytes(4, "little", signed=False)
    payload[4:] = payload_data
    return bytes(payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="通过 Frida 原生链路单次发送文本消息。")
    parser.add_argument("--receiver", default="filehelper", help="接收方 wxid，文件传输助手通常是 filehelper")
    parser.add_argument("--message", required=True, help="要发送的文本")
    parser.add_argument("--at-user", default="", help="@ 用户 wxid，默认空")
    parser.add_argument("--pid", type=int, help="WeChat 主进程 PID")
    parser.add_argument("--task-id", type=int, default=0x20000090, help="自定义 task id")
    parser.add_argument("--timeout", type=float, default=25.0, help="等待发送完成的秒数")
    parser.add_argument("--context-timeout", type=float, default=12.0, help="等待捕获真实 StartTask x0 的秒数")
    parser.add_argument("--attach-timeout", type=float, default=20.0, help="Frida attach/create/load 单步超时秒数，避免 TUI 卡在重注入。")
    parser.add_argument("--controlled-restart-on-attach-timeout", action="store_true", help="attach 超时后受控重启 WeChat 并重试一次。")
    parser.add_argument(
        "--post-finish-hold",
        type=float,
        default=5.0,
        help="最后一次 finish 到最终释放之间的最小安全窗口；常驻发送之间不再硬等该时长。",
    )
    parser.add_argument(
        "--inter-send-delay",
        type=float,
        default=0.5,
        help="常驻文本发送之间的最小节流秒数，默认 0.5 秒。",
    )
    parser.add_argument("--execute", action="store_true", help="真的触发 native 发送；默认只构造数据不 attach")
    parser.add_argument("--attach-smoke", action="store_true", help="只 attach/load/inspect/unload，不触发发送，用于安全验证 hooks 能安装。")
    parser.add_argument(
        "--i-accept-freeze-risk",
        action="store_true",
        help="已知当前原生发送会导致 WeChat 发送后卡死；必须显式确认才允许执行。",
    )
    parser.add_argument(
        "--keep-frida-helper",
        action="store_true",
        help="调试用：退出时不兜底清理 frida-helper。默认会清理，保证本测试器不留下驻留注入资源。",
    )
    parser.add_argument(
        "--health-check-seconds",
        type=float,
        default=3.0,
        help="释放 Frida 后观察 WeChat CPU/状态的秒数，默认 3 秒。",
    )
    parser.add_argument(
        "--manual-release-file",
        type=Path,
        help="成功后保持 hooks/session，直到该文件出现才执行清理。",
    )
    parser.add_argument(
        "--command-dir",
        type=Path,
        help="常驻 session 的连续发送命令目录。",
    )
    parser.add_argument("--output", type=Path, default=Path("/tmp/wechat-native-send-once.jsonl"))
    return parser.parse_args()


def progress(step: int, total: int, text: str) -> None:
    print(f"[{step}/{total}] {text}", flush=True)


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


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def controlled_restart_wechat(pid: int) -> int:
    print(f"[attach] 正在受控重启 WeChat PID {pid}，用于清理脏注入状态。", flush=True)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 8.0
    while pid_alive(pid) and time.time() < deadline:
        time.sleep(0.2)
    if pid_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    subprocess.run(["open", "-a", "WeChat"], check=False)
    deadline = time.time() + 30.0
    while time.time() < deadline:
        try:
            new_pid = find_wechat_pid()
            if new_pid != pid:
                print(f"[attach] WeChat 已重启：old_pid={pid} new_pid={new_pid}。", flush=True)
                return new_pid
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("受控重启后未找到新的 WeChat 主进程")


def attach_and_load_agent(frida_module, pid: int, agent_path: Path, on_message, timeout: float):
    device = run_with_timeout("frida.get_local_device", frida_module.get_local_device, timeout)
    session = run_with_timeout("frida.attach", lambda: device.attach(pid), timeout)
    script = run_with_timeout("frida.create_script", lambda: session.create_script(agent_path.read_text(encoding="utf-8")), timeout)
    script.on("message", on_message)
    run_with_timeout("frida.script.load", script.load, timeout)
    return session, script


def wait_for_manual_release(
    release_file: Path | None,
    command_dir: Path | None = None,
    command_handler=None,
    release_handler=None,
) -> None:
    if release_file is None:
        if release_handler is not None:
            release_handler()
        return
    ready_file = Path(f"{release_file}.ready")
    if command_dir is not None:
        command_dir.mkdir(parents=True, exist_ok=True)

    def announce_ready() -> None:
        ready_file.write_text("ready\n", encoding="utf-8")
        print(
            "[手动释放] 操作已完成，Frida 保持连接；等待用户继续发送或在 Web 控制台手动释放。",
            flush=True,
        )

    def command_id_from_path(path: Path) -> str:
        stem = path.stem
        return stem.split("-", 1)[1] if "-" in stem else stem

    announce_ready()
    try:
        while True:
            if release_file.exists():
                break
            command_paths = sorted(command_dir.glob("*.json")) if command_dir is not None else []
            if not command_paths:
                time.sleep(0.2)
                continue
            ready_file.unlink(missing_ok=True)
            for command_path in command_paths:
                command_id = command_id_from_path(command_path)
                try:
                    command = json.loads(command_path.read_text(encoding="utf-8"))
                    command_id = str(command.get("command_id") or command_id)
                    command_path.unlink(missing_ok=True)
                    if command_handler is None:
                        raise RuntimeError("persistent command handler is unavailable")
                    print(f"[命令:{command_id}] 开始连续发送。", flush=True)
                    command_handler(command)
                    status_path = command_dir / f"{command_id}.done"
                    temporary = command_dir / f".{command_id}.done.tmp"
                    temporary.write_text("ok\n", encoding="utf-8")
                    temporary.replace(status_path)
                    status_path.chmod(0o644)
                    print(f"[命令:{command_id}] 连续发送完成。", flush=True)
                except Exception as exc:
                    command_path.unlink(missing_ok=True)
                    if command_dir is not None:
                        status_path = command_dir / f"{command_id}.failed"
                        temporary = command_dir / f".{command_id}.failed.tmp"
                        temporary.write_text(str(exc), encoding="utf-8")
                        temporary.replace(status_path)
                        status_path.chmod(0o644)
                    print(f"[命令:{command_id}] 连续发送失败：{exc}", file=sys.stderr, flush=True)
                    raise
            announce_ready()
            time.sleep(0.2)
    finally:
        ready_file.unlink(missing_ok=True)
    print("[手动释放] 已收到释放指令，进入最终 drain 检查。", flush=True)
    if release_handler is not None:
        release_handler()
    print("[手动释放] 最终 drain 完成，开始 force_cleanup -> unload -> detach。", flush=True)


def cleanup_frida_helpers(parent_pid: int | None = None) -> int:
    parent_pid = os.getpid() if parent_pid is None else parent_pid
    pids = frida_helper_pids(parent_pid)
    if not pids:
        return 0
    for helper_pid in pids:
        try:
            os.kill(int(helper_pid), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
    deadline = time.time() + 1.0
    remaining = frida_helper_pids(parent_pid)
    while remaining and time.time() < deadline:
        time.sleep(0.05)
        remaining = frida_helper_pids(parent_pid)
    for helper_pid in remaining:
        try:
            os.kill(int(helper_pid), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass
    return len(pids)


def frida_helper_pids(parent_pid: int | None = None) -> list[str]:
    parent_pid = os.getpid() if parent_pid is None else parent_pid
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        check=False,
        text=True,
        capture_output=True,
    )
    pids: list[str] = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        pid_text, ppid_text, command = fields
        if ppid_text != str(parent_pid):
            continue
        if "/.cache/frida/" in command and "/frida-helper" in command:
            pids.append(pid_text)
    return pids


def wait_frida_helpers_gone(seconds: float = 3.0, parent_pid: int | None = None) -> int:
    parent_pid = os.getpid() if parent_pid is None else parent_pid
    deadline = time.time() + max(0.0, seconds)
    pids = frida_helper_pids(parent_pid)
    while pids and time.time() < deadline:
        time.sleep(min(0.25, max(0.05, deadline - time.time())))
        pids = frida_helper_pids(parent_pid)
    return len(pids)


def shutdown_frida_runtime(frida_module, timeout: float = 10.0) -> bool:
    """Close frida-python's global DeviceManager before helper fallback cleanup."""
    done = threading.Event()
    errors: list[str] = []

    def shutdown() -> None:
        try:
            frida_module.shutdown()
        except Exception as exc:  # noqa: BLE001 - cleanup must keep going
            errors.append(str(exc))
        finally:
            done.set()

    threading.Thread(target=shutdown, name="frida-runtime-shutdown", daemon=True).start()
    if not done.wait(max(1.0, timeout)):
        print(f"[清理] frida.shutdown 超过 {timeout:.0f} 秒仍未返回。", flush=True)
        return False
    if errors:
        print(f"[清理] frida.shutdown 返回异常：{errors[-1]}", flush=True)
        return False
    print("[清理] Frida DeviceManager 已关闭。", flush=True)
    return True


def read_wechat_health(pid: int) -> tuple[str, float, str] | None:
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "state=,%cpu=,command="],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    if not out:
        return None
    match = re.match(r"^(\S+)\s+([0-9.]+)\s+(.*)$", out)
    if not match:
        return (out, -1.0, "")
    return (match.group(1), float(match.group(2)), match.group(3))


def watch_wechat_health(pid: int, seconds: float) -> None:
    if seconds <= 0:
        return
    deadline = time.time() + seconds
    samples: list[tuple[str, float, str]] = []
    missing_samples = 0
    while time.time() < deadline:
        item = read_wechat_health(pid)
        if item is not None:
            samples.append(item)
        else:
            missing_samples += 1
        time.sleep(min(0.5, max(0.05, deadline - time.time())))
    if read_wechat_health(pid) is None:
        print(f"[健康] WeChat 主进程 PID {pid} 已退出；疑似闪退/被系统重启。", flush=True)
        return
    if not samples:
        print("[健康] 未找到 WeChat 主进程；可能已退出。", flush=True)
        return
    state, cpu, _ = samples[-1]
    max_cpu = max(sample[1] for sample in samples)
    high_samples = sum(1 for sample in samples if sample[1] >= 80.0)
    high_ratio = high_samples / len(samples)
    sustained_high = cpu >= 80.0 or high_ratio >= 0.30 or high_samples >= 6
    if sustained_high:
        print(f"[健康] WeChat 疑似卡死：state={state} cpu_now={cpu:.1f}% cpu_max={max_cpu:.1f}%。", flush=True)
    elif missing_samples:
        print(f"[健康] WeChat 状态目前正常，但监测中有 {missing_samples} 次采样未找到原 PID。", flush=True)
    elif max_cpu >= 80.0:
        print(f"[健康] WeChat 状态正常：state={state} cpu_now={cpu:.1f}% cpu_max={max_cpu:.1f}%（曾有瞬时峰值）。", flush=True)
    else:
        print(f"[健康] WeChat 状态正常：state={state} cpu_now={cpu:.1f}% cpu_max={max_cpu:.1f}%。", flush=True)


def main() -> int:
    args = parse_args()
    proto = build_text_proto(args.receiver, args.message, args.at_user)
    payload = build_send_payload(args.task_id)

    progress(1, 6, "构造 text protobuf 和 MMStartTask payload")
    print(f"      receiver={args.receiver!r} message_len={len(args.message.encode('utf-8'))} proto_len={len(proto)} payload_len={len(payload)}", flush=True)
    if len(payload) != 0x1A0:
        raise RuntimeError(f"payload length mismatch: {len(payload)}")

    if not args.execute and not args.attach_smoke:
        print("DRY RUN：没有 attach WeChat，也没有发送。当前真实执行存在发送后卡死风险，需 --execute --i-accept-freeze-risk。", flush=True)
        return 0
    if args.execute and not args.i_accept_freeze_risk:
        raise RuntimeError(
            "安全拦截：当前 native 单次发送已确认能发出消息，但发送后会让 WeChat 卡死；"
            "若只是研究复现，需显式加 --i-accept-freeze-risk。"
        )

    try:
        import frida
    except ModuleNotFoundError as exc:
        raise RuntimeError("缺少 Python frida 模块；执行 python3 -m pip install --user frida") from exc

    finished = threading.Event()
    finish_timed_out = threading.Event()
    failed = threading.Event()
    args.output.unlink(missing_ok=True)

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
            print(f"[事件] 已捕获 x0={payload_obj.get('x0')}", flush=True)
        elif typ == "triggering":
            print(f"[事件] 已调用 MMStartTask task_id={payload_obj.get('task_id')}", flush=True)
        elif typ == "req2buf_inserted":
            print(f"[事件] Req2Buf 已挂入 fake object：{payload_obj.get('address')}", flush=True)
        elif typ == "protobuf_written":
            print(f"[事件] protobuf 已写入 AutoBuffer，len={payload_obj.get('length')}", flush=True)
        elif typ == "req2buf_exit_pending_ack":
            print("[事件] Req2Buf 已退出，等待真正 Buf2Resp ack 后再清理。", flush=True)
        elif typ == "log_buf2resp_seen":
            print(f"[事件] 日志回调看到 task_id={payload_obj.get('task_id')}，不在此处清理。", flush=True)
        elif typ == "buf2resp_ack":
            print(
                f"[事件] 真正 Buf2Resp ack 已匹配，len={payload_obj.get('response_len')}；开始清理 fake 指针。",
                flush=True,
            )
        elif typ in {"insert_cleanup", "finish", "finish_timeout_cleanup"}:
            strategy = payload_obj.get("strategy")
            suffix = f" strategy={strategy}" if strategy else ""
            print(f"[事件] {typ}：资源已清理{suffix}", flush=True)
            if typ == "finish_timeout_cleanup":
                finish_timed_out.set()
            if typ in {"finish", "finish_timeout_cleanup"}:
                finished.set()
        elif str(typ).endswith("error"):
            print(f"[事件] {typ}: {payload_obj}", file=sys.stderr, flush=True)
            failed.set()

    pid = args.pid or find_wechat_pid()
    progress(2, 6, f"连接 WeChat 主进程 PID {pid}")
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
                progress(2, 6, f"重试连接 WeChat 主进程 PID {pid}")
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
        details = script.exports_sync.inspect()
        save({"type": "agent_ready", "details": details})
        progress(3, 6, "临时 Frida hooks 已安装，等待真实 StartTask 上下文")
        print(
            "      "
            f"send={details['hook_details']['sendFuncAddr']} "
            f"req2buf={details['hook_details']['req2bufEnterAddr']} "
            f"blr={details['hook_details']['blrX8Addr']} "
            f"ack={details['hook_details']['buf2RespAckHookAddr']}",
            flush=True,
        )

        last_finish_at = [0.0]

        def mark_finish() -> None:
            last_finish_at[0] = time.monotonic()

        def final_text_drain() -> None:
            if last_finish_at[0] <= 0 or args.post_finish_hold <= 0:
                return
            elapsed = time.monotonic() - last_finish_at[0]
            remaining = max(0.0, args.post_finish_hold - elapsed)
            if remaining > 0:
                print(
                    f"[最终排空] 距最后一次文本 ack 仅 {elapsed:.1f} 秒，补足 {remaining:.1f} 秒安全窗口后释放。",
                    flush=True,
                )
                time.sleep(remaining)
            else:
                print(f"[最终排空] 最后一次文本 ack 已过去 {elapsed:.1f} 秒，可立即释放。", flush=True)

        def execute_persistent_text(command: dict[str, object]) -> None:
            receiver = str(command.get("receiver") or "").strip()
            content = str(command.get("content") or "")
            at_user = str(command.get("at_user") or "").strip()
            sequence = int(command.get("sequence") or 0)
            task_id = (args.task_id + max(1, sequence)) & 0xFFFFFFFF
            if not receiver or not content:
                raise RuntimeError("连续文本发送缺少 receiver 或 content")

            deadline = time.time() + args.context_timeout
            while time.time() < deadline:
                status = script.exports_sync.status()
                if status.get("context_ready"):
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("连续发送等待 StartTask 上下文超时")

            finished.clear()
            finish_timed_out.clear()
            failed.clear()
            command_proto = build_text_proto(receiver, content, at_user)
            command_payload = build_send_payload(task_id)
            result = script.exports_sync.trigger_text(task_id, command_proto.hex(), command_payload.hex())
            save({"type": "persistent_trigger_result", "command_id": command.get("command_id"), "result": result})
            if not result.get("ok"):
                raise RuntimeError(f"连续文本 trigger 失败: {result}")
            if not finished.wait(args.timeout):
                status = script.exports_sync.status()
                script.exports_sync.force_cleanup()
                raise RuntimeError(f"连续文本发送等待 finish 超时: {status}")
            if finish_timed_out.is_set():
                raise RuntimeError("连续文本发送未收到 Buf2Resp ack，已由 Agent 超时清理")
            if failed.is_set():
                raise RuntimeError("连续文本发送收到 Frida 错误事件")
            mark_finish()
            if args.inter_send_delay > 0:
                time.sleep(args.inter_send_delay)

        if args.attach_smoke and not args.execute:
            print("ATTACH SMOKE：hooks 已加载并完成 inspect；不等待上下文、不发送。", flush=True)
            wait_for_manual_release(args.manual_release_file, args.command_dir, execute_persistent_text, final_text_drain)
            return 0

        deadline = time.time() + args.context_timeout
        while time.time() < deadline:
            status = script.exports_sync.status()
            if status.get("context_ready"):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("等待 StartTask 上下文超时；请保持微信在线并有一次普通网络活动后重试")

        progress(4, 6, "触发一次 native 文本发送")
        result = script.exports_sync.trigger_text(args.task_id, proto.hex(), payload.hex())
        save({"type": "trigger_result", "result": result})
        if not result.get("ok"):
            raise RuntimeError(f"trigger failed: {result}")

        progress(5, 6, f"等待发送链路完成或超时 {args.timeout:.0f} 秒")
        if not finished.wait(args.timeout):
            status = script.exports_sync.status()
            save({"type": "timeout_status", "status": status})
            print(f"等待结束：未收到 finish，当前状态 {status}；执行强制清理。", file=sys.stderr, flush=True)
            script.exports_sync.force_cleanup()
            return 4
        if failed.is_set():
            return 2
        if finish_timed_out.is_set():
            return 4
        mark_finish()
        wait_for_manual_release(args.manual_release_file, args.command_dir, execute_persistent_text, final_text_drain)
        return 0
    finally:
        progress(6, 6, "释放 Frida 资源：保活结束 -> force_cleanup -> unload -> detach")
        done = threading.Event()
        cleanup_errors: list[str] = []

        def cleanup() -> None:
            try:
                try:
                    script.exports_sync.force_cleanup()
                except Exception as exc:
                    cleanup_errors.append(f"force_cleanup: {exc}")
                try:
                    script.unload()
                except Exception as exc:
                    cleanup_errors.append(f"script.unload: {exc}")
                try:
                    session.detach()
                except Exception as exc:
                    cleanup_errors.append(f"session.detach: {exc}")
            finally:
                done.set()

        threading.Thread(target=cleanup, daemon=True).start()
        cleanup_finished = done.wait(30.0)
        if cleanup_finished and not cleanup_errors:
            print("Frida script 已卸载，session 已分离。", flush=True)
        elif cleanup_finished:
            print(f"Frida cleanup 返回异常：{'; '.join(cleanup_errors)}；进入 helper 兜底清理。", flush=True)
        else:
            print("Frida cleanup 超时：进入 helper 兜底清理。", flush=True)
        shutdown_frida_runtime(frida, 10.0)
        if args.keep_frida_helper:
            print("Frida helper 兜底清理已跳过（--keep-frida-helper）。", flush=True)
        else:
            remaining = wait_frida_helpers_gone(5.0)
            killed = cleanup_frida_helpers() if remaining else 0
            print(f"Frida helper 兜底清理完成：等待后残留 {remaining} 个，清理 {killed} 个。", flush=True)
        watch_wechat_health(pid, args.health_check_seconds)
        print(f"事件日志：{args.output}", flush=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("发送测试已由用户结束。", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"发送测试失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
