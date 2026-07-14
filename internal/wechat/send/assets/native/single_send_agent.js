'use strict';

const RESOURCE_SUFFIX = '/Contents/Resources/wechat.dylib';

const OFFSETS = {
    sendFuncAddr: 0x5121458,
    sendFuncHookDelta: 0x10,
    req2bufEnterHookAddr: 0x3e5930c,
    req2bufExitHookAddr: 0x3e5a260,
    blrX8HookAddr: 0x3e5938c,
    autoBufferWriteFunc: 0x3e7ff18,
    // 上游真正用于 ack/receiver 的 buf2resp 数据点；这里 x20=data, x0=len, sp+0x140≈taskId。
    buf2RespAckHookAddr: 0x3e7eaf0,
    // 这是 MMStartTask/OnTaskEnd 附近的日志包装点，只能做观测，不能当 ack 清理点。
    logBuf2RespHookAddr: 0x51233f8,
};

let listeners = [];
let triggerX0 = ptr(0);
let contextReady = false;
let sending = false;
let taskIdGlobal = 0;
let textProtoHexGlobal = '';
let sendMsgType = '';
let insertedAddr = ptr(0);
let insertedOriginal = ptr(0);
let inserted = false;
let protoWritten = false;
let cleanupDone = false;
let logBuf2RespSeen = false;
let ackSeen = false;
let ackReadErrors = 0;

let retOneStub = ptr(0);
let fakeVtable = ptr(0);
let textCgiAddr = ptr(0);
let sendTextMessageAddr = ptr(0);
let textMessageAddr = ptr(0);
let textProtoDataAddr = ptr(0);
let triggerX1Payload = ptr(0);
let nativeAutoBufferWrite = null;
let sendFunc = null;

function emit(type, extra) {
    const payload = Object.assign({type: type}, extra || {});
    send(payload);
}

function resourceModule() {
    const modules = Process.enumerateModules().filter(function (module) {
        return module.path.endsWith(RESOURCE_SUFFIX);
    });
    if (modules.length !== 1) {
        throw new Error('expected one Resources/wechat.dylib, got ' + modules.length);
    }
    return modules[0];
}

function readable(address) {
    try {
        if (!address || address.isNull()) {
            return false;
        }
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (_) {
        return false;
    }
}

function patchString(addr, plainStr) {
    const bytes = [];
    for (let i = 0; i < plainStr.length; i++) {
        bytes.push(plainStr.charCodeAt(i));
    }
    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0);
}

function hexToByteArray(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return bytes;
}

function setupRetOneStub() {
    retOneStub = Memory.alloc(Process.pageSize);
    Memory.patchCode(retOneStub, 8, function (code) {
        code.writeByteArray([0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]);
    });

    fakeVtable = Memory.alloc(512);
    for (let i = 0; i < 64; i++) {
        fakeVtable.add(i * 8).writePointer(retOneStub);
    }
}

function setupTextObjects() {
    textCgiAddr = Memory.alloc(128);
    sendTextMessageAddr = Memory.alloc(256);
    textMessageAddr = Memory.alloc(256);
    textProtoDataAddr = Memory.alloc(64 * 1024);
    triggerX1Payload = Memory.alloc(0x1a0);

    patchString(textCgiAddr, '/cgi-bin/micromsg-bin/newsendmsg');

    sendTextMessageAddr.add(0x00).writeU64(0);
    sendTextMessageAddr.add(0x08).writeU64(0);
    sendTextMessageAddr.add(0x10).writeU64(0);
    sendTextMessageAddr.add(0x18).writeU64(1);
    sendTextMessageAddr.add(0x20).writeU32(0);
    sendTextMessageAddr.add(0x28).writePointer(textMessageAddr);

    textMessageAddr.add(0x00).writePointer(fakeVtable);
    textMessageAddr.add(0x08).writeU32(0);
    textMessageAddr.add(0x0c).writeU32(0x20a);
    textMessageAddr.add(0x10).writeU64(0x3);
    textMessageAddr.add(0x18).writePointer(textCgiAddr);
    textMessageAddr.add(0x20).writeU64(uint64('0x20'));
}

function clearInserted(reason, strategy) {
    if (!inserted || insertedAddr.isNull()) {
        return false;
    }
    const mode = strategy || 'restore';
    try {
        const replacement = mode === 'null' ? ptr(0) : insertedOriginal;
        insertedAddr.writePointer(replacement);
        emit('insert_cleanup', {
            reason: reason,
            strategy: mode,
            address: insertedAddr.toString(),
            original: insertedOriginal.toString(),
            replacement: replacement.toString(),
            task_id: taskIdGlobal,
        });
    } catch (e) {
        emit('insert_cleanup_error', {reason: reason, strategy: mode, error: String(e)});
    }
    inserted = false;
    insertedAddr = ptr(0);
    insertedOriginal = ptr(0);
    cleanupDone = true;
    return true;
}

function attachHooks(module) {
    const sendFuncAddr = module.base.add(OFFSETS.sendFuncAddr);
    const sendHookAddr = sendFuncAddr.add(OFFSETS.sendFuncHookDelta);
    const req2bufEnterAddr = module.base.add(OFFSETS.req2bufEnterHookAddr);
    const req2bufExitAddr = module.base.add(OFFSETS.req2bufExitHookAddr);
    const blrX8Addr = module.base.add(OFFSETS.blrX8HookAddr);
    const autoBufferWriteAddr = module.base.add(OFFSETS.autoBufferWriteFunc);
    const buf2RespAckAddr = module.base.add(OFFSETS.buf2RespAckHookAddr);
    const logBuf2RespAddr = module.base.add(OFFSETS.logBuf2RespHookAddr);

    sendFunc = new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);
    nativeAutoBufferWrite = new NativeFunction(autoBufferWriteAddr, 'int', ['pointer', 'pointer', 'int']);

    listeners.push(Interceptor.attach(sendHookAddr, {
        onEnter: function () {
            if (!contextReady) {
                triggerX0 = this.context.x0;
                contextReady = true;
                emit('context_captured', {
                    x0: triggerX0.toString(),
                    x1: this.context.x1.toString(),
                });
            }
        },
    }));

    listeners.push(Interceptor.attach(req2bufEnterAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || !this.context.x1.equals(ptr(taskIdGlobal))) {
                return;
            }
            // 当前 4.1.11.54 的 hook 点在 `mov x24, x19` 前，所以用 x19 作为 base。
            const base = this.context.x19;
            if (!readable(base.add(0x60))) {
                emit('req2buf_insert_error', {error: 'base+0x60 unreadable', base: base.toString()});
                return;
            }
            insertedAddr = base.add(0x60);
            insertedOriginal = insertedAddr.readPointer();
            insertedAddr.writePointer(sendTextMessageAddr);
            inserted = true;
            emit('req2buf_inserted', {
                task_id: taskIdGlobal,
                base: base.toString(),
                address: insertedAddr.toString(),
                original: insertedOriginal.toString(),
                replacement: sendTextMessageAddr.toString(),
            });
        },
    }));

    listeners.push(Interceptor.attach(blrX8Addr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || this.context.x20.toUInt32() !== taskIdGlobal) {
                return;
            }
            if (!textProtoHexGlobal || textProtoHexGlobal.length === 0) {
                emit('protobuf_error', {error: 'empty proto hex'});
                return;
            }
            const finalPayload = hexToByteArray(textProtoHexGlobal);
            textProtoDataAddr.writeByteArray(finalPayload);
            // Hook point is before `add x1, sp, #0x140`; compute AutoBuffer manually.
            const autoBuffer = this.context.sp.add(0x140);
            nativeAutoBufferWrite(autoBuffer, textProtoDataAddr, finalPayload.length);
            // Later instructions set x1/x2/x3/x4, then `blr x8`; redirect x8 to retOneStub.
            this.context.x8 = retOneStub;
            protoWritten = true;
            emit('protobuf_written', {
                task_id: taskIdGlobal,
                length: finalPayload.length,
                auto_buffer: autoBuffer.toString(),
            });
        },
    }));

    listeners.push(Interceptor.attach(req2bufExitAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || !inserted) {
                return;
            }
            // 这里只做状态提示，不清理。真正清理必须等 buf2resp ack。
            emit('req2buf_exit_pending_ack', {
                task_id: taskIdGlobal,
                inserted_address: insertedAddr.toString(),
                x0: this.context.x0.toString(),
                x20: this.context.x20.toString(),
                x25: this.context.x25.toString(),
            });
        },
    }));

    listeners.push(Interceptor.attach(logBuf2RespAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || !this.context.x1.equals(ptr(taskIdGlobal))) {
                return;
            }
            // 这个点能看到 taskId，但不是 protobuf ack 数据点；只做观测，绝不在这里清理。
            logBuf2RespSeen = true;
            emit('log_buf2resp_seen', {
                task_id: taskIdGlobal,
                x0: this.context.x0.toString(),
                x1: this.context.x1.toString(),
                x4: this.context.x4.toString(),
            });
        },
    }));

    listeners.push(Interceptor.attach(buf2RespAckAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0) {
                return;
            }

            let respTaskId = 0;
            let responseLen = -1;
            try {
                respTaskId = this.context.sp.add(0x140).readS32();
                responseLen = this.context.x0.toInt32();
            } catch (e) {
                ackReadErrors += 1;
                if (ackReadErrors <= 3) {
                    emit('buf2resp_ack_probe_error', {error: String(e)});
                }
                return;
            }

            if (respTaskId !== taskIdGlobal) {
                return;
            }

            ackSeen = true;
            emit('buf2resp_ack', {
                task_id: taskIdGlobal,
                response_len: responseLen,
                response_ptr: this.context.x20.toString(),
                sp_task_id_addr: this.context.sp.add(0x140).toString(),
            });

            // 上游策略：ack 到达后把 Req2Buf 插入槽置 NULL，避免 OnTaskEnd 继续释放 Frida fake object。
            clearInserted('buf2resp_ack', 'null');
            const finishedTaskId = taskIdGlobal;
            sending = false;
            emit('finish', {
                task_id: finishedTaskId,
                inserted: inserted,
                proto_written: protoWritten,
                log_buf2resp_seen: logBuf2RespSeen,
                ack_seen: ackSeen,
            });
            taskIdGlobal = 0;
            sendMsgType = '';
        },
    }));

    return {
        sendFuncAddr: sendFuncAddr.toString(),
        sendHookAddr: sendHookAddr.toString(),
        req2bufEnterAddr: req2bufEnterAddr.toString(),
        req2bufExitAddr: req2bufExitAddr.toString(),
        blrX8Addr: blrX8Addr.toString(),
        autoBufferWriteFunc: autoBufferWriteAddr.toString(),
        buf2RespAckHookAddr: buf2RespAckAddr.toString(),
        logBuf2RespHookAddr: logBuf2RespAddr.toString(),
        instructions: {
            send: Instruction.parse(sendFuncAddr).toString(),
            send_hook: Instruction.parse(sendHookAddr).toString(),
            req2buf_enter: Instruction.parse(req2bufEnterAddr).toString(),
            req2buf_exit: Instruction.parse(req2bufExitAddr).toString(),
            blr_x8: Instruction.parse(blrX8Addr).toString(),
            auto_buffer_write: Instruction.parse(autoBufferWriteAddr).toString(),
            buf2resp_ack: Instruction.parse(buf2RespAckAddr).toString(),
            log_buf2resp: Instruction.parse(logBuf2RespAddr).toString(),
        },
    };
}

function triggerText(taskId, protoHex, payloadHex) {
    if (!contextReady || triggerX0.isNull()) {
        return {ok: false, error: 'context_not_ready'};
    }
    if (sending) {
        return {ok: false, error: 'already_sending'};
    }
    if (!taskId || taskId <= 0) {
        return {ok: false, error: 'bad_task_id'};
    }
    const payloadBytes = hexToByteArray(payloadHex);
    if (payloadBytes.length !== 0x1a0) {
        return {ok: false, error: 'bad_payload_len_' + payloadBytes.length};
    }

    taskIdGlobal = taskId >>> 0;
    textProtoHexGlobal = protoHex;
    sendMsgType = 'text';
    inserted = false;
    protoWritten = false;
    cleanupDone = false;
    logBuf2RespSeen = false;
    ackSeen = false;
    ackReadErrors = 0;

    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);

    triggerX1Payload.writeByteArray(payloadBytes);
    triggerX1Payload.add(0x18).writePointer(textCgiAddr);
    triggerX1Payload.add(0xb8).writePointer(triggerX1Payload.add(0xc0));
    triggerX1Payload.add(0x190).writePointer(triggerX1Payload.add(0x198));

    sending = true;
    emit('triggering', {
        task_id: taskIdGlobal,
        x0: triggerX0.toString(),
        x1: triggerX1Payload.toString(),
        proto_len: protoHex.length / 2,
    });

    try {
        const rv = sendFunc(triggerX0, triggerX1Payload);
        emit('trigger_returned', {task_id: taskIdGlobal, return_value: rv.toString()});
        // 兜底：如果 buf2resp 没回来，别把 X19+0x60 的替换指针长期留住。
        setTimeout(function () {
            if (sending && inserted) {
                clearInserted(logBuf2RespSeen ? 'timeout_after_log_buf2resp_no_ack' : 'timeout_no_buf2resp_ack', 'restore');
                sending = false;
                emit('finish_timeout_cleanup', {
                    task_id: taskIdGlobal,
                    proto_written: protoWritten,
                    log_buf2resp_seen: logBuf2RespSeen,
                    ack_seen: ackSeen,
                });
                taskIdGlobal = 0;
            }
        }, 12000);
        return {ok: true, task_id: taskIdGlobal};
    } catch (e) {
        clearInserted('trigger_exception');
        sending = false;
        const err = String(e);
        emit('trigger_error', {task_id: taskIdGlobal, error: err});
        taskIdGlobal = 0;
        return {ok: false, error: err};
    }
}

const module = resourceModule();
setupRetOneStub();
setupTextObjects();
const hookDetails = attachHooks(module);

rpc.exports = {
    inspect: function () {
        return {
            pid: Process.id,
            arch: Process.arch,
            module_base: module.base.toString(),
            module_path: module.path,
            offsets: OFFSETS,
            hook_details: hookDetails,
            context_ready: contextReady,
            trigger_x0: triggerX0.toString(),
        };
    },
    status: function () {
        return {
            context_ready: contextReady,
            sending: sending,
            task_id: taskIdGlobal,
            inserted: inserted,
            proto_written: protoWritten,
            cleanup_done: cleanupDone,
            log_buf2resp_seen: logBuf2RespSeen,
            ack_seen: ackSeen,
            ack_read_errors: ackReadErrors,
            trigger_x0: triggerX0.toString(),
        };
    },
    // Frida Python maps snake_case accessors to camelCase RPC names. Export both aliases.
    triggerText: function (taskId, protoHex, payloadHex) {
        return triggerText(taskId, protoHex, payloadHex);
    },
    trigger_text: function (taskId, protoHex, payloadHex) {
        return triggerText(taskId, protoHex, payloadHex);
    },
    forceCleanup: function () {
        clearInserted('force_cleanup', 'restore');
        sending = false;
        taskIdGlobal = 0;
        return true;
    },
    force_cleanup: function () {
        clearInserted('force_cleanup', 'restore');
        sending = false;
        taskIdGlobal = 0;
        return true;
    },
};
