'use strict';

const RESOURCE_SUFFIX = '/Contents/Resources/wechat.dylib';

const OFFSETS = {
    sendFuncAddr: 0x5121458,
    sendFuncHookDelta: 0x10,
    // Looks up the default MMSTN manager and calls MMStartTask internally.
    // This is the idle-process fallback when no unrelated StartTask call has
    // been observed since the one-shot Frida session attached.
    defaultStartTaskFuncAddr: 0x51173b0,
    req2bufEnterHookAddr: 0x3e5930c,
    req2bufExitHookAddr: 0x3e5a260,
    blrX8HookAddr: 0x3e5938c,
    autoBufferWriteFunc: 0x3e7ff18,
    buf2RespAckHookAddr: 0x3e7eaf0,
    logBuf2RespHookAddr: 0x51233f8,

    uploadImageAddr: 0x529c1fc,
    uploadImageEntryWrapperAddr: 0x525a008,
    cndOnCompleteAddr: 0x3e15be8,
    uploadGetCallbackWrapperAddr: 0x525afa0,
    uploadGetCallbackWrapperFuncAddr: 0x3e15484,
    uploadOnCompleteAddr: 0x525b758,
    uploadOnCompleteFuncAddr: 0x3e16608,
    // StartC2CUpload preflight probes. These are observation-only and let the
    // host distinguish missing manager RSA state from request/path rejection;
    // both otherwise collapse to signed -20003.
    uploadRsaPreflightAddr: 0x529bba0,
};

let triggerX0 = ptr(0);
let contextReady = false;
let uploadGlobalX0 = ptr(0);
let uploadContextReady = false;
let sending = false;
let taskIdGlobal = 0;
let sendMsgType = '';
let imgProtoHexGlobal = '';
let insertedAddr = ptr(0);
let insertedOriginal = ptr(0);
let inserted = false;
let protoWritten = false;
let cleanupDone = false;
let logBuf2RespSeen = false;
let ackSeen = false;
let ackReadErrors = 0;
let hooksDetached = false;
let uploadHookListeners = [];
let autoDetachHooksAfterAck = false;
let autoDetachUploadHooksAfterFinish = false;

let retOneStub = ptr(0);
let fakeVtable = ptr(0);
let imgCgiAddr = ptr(0);
let sendImgMessageAddr = ptr(0);
let imgMessageAddr = ptr(0);
let imgProtoDataAddr = ptr(0);
let triggerX1Payload = ptr(0);
let textCgiAddr = ptr(0);
let sendTextMessageAddr = ptr(0);
let textMessageAddr = ptr(0);
let textProtoDataAddr = ptr(0);
let textTriggerX1Payload = ptr(0);
let nativeAutoBufferWrite = null;
let sendFunc = null;
let defaultStartTaskFunc = null;
let uploadImageFunc = null;
let uploadImageEntryWrapperFunc = null;

let imageIdAddr = ptr(0);
let md5Addr = ptr(0);
let uploadAesKeyAddr = ptr(0);
let imagePathAddr = ptr(0);
let uploadImageX1 = ptr(0);
let uploadFunc1Addr = ptr(0);
let uploadFunc2Addr = ptr(0);
let uploadCallback = ptr(0);
let nativeCalloc = null;
let nativeMmap = null;
let nativeFree = null;
let nativeMunmap = null;
let persistentAllocs = [];
let imageUploadEverTriggered = false;
let imageGenerations = [];
let activeImageGeneration = null;
let imageGenerationSequence = 0;
let imageUploadSequence = 0;
let imageGenerationRetentionMs = 90000;
// The captured synthetic upload profile stores file_id with a fixed 38-byte
// length. Keep the generated ASCII identifier inside that boundary; otherwise
// long group receiver IDs are truncated into an inconsistent request.
const MAX_PROFILE_FILE_ID_LENGTH = 38;
let learnedGetCallbackFunc = ptr(0);
let learnedOnCompleteFunc = ptr(0);
let learnedGetCallbackSamples = 0;
let learnedOnCompleteSamples = 0;
let allowStaticCallbackFallback = false;
let forceStaticCallbackProfile = false;
let uploadLifecycleTemplateMode = false;
let uploadCallbackOverrideEnabled = true;
let uploadTemplateReady = false;
let uploadTemplateBase = ptr(0);
let uploadTemplateBytes = null;
let uploadFunc1TemplateBase = ptr(0);
let uploadFunc2TemplateBase = ptr(0);
let uploadFunc1TemplateBytes = null;
let uploadFunc2TemplateBytes = null;
let uploadTemplateSummary = {};
let uploadCallbackTemplateReady = false;
let uploadCallbackTemplateApplied = false;
let uploadCallbackTemplateBase = ptr(0);
let uploadCallbackTemplateBytes = null;
let uploadCallbackTemplateSummary = {};
let imageSendTemplateReady = false;
let imageSendObjectTemplateBase = ptr(0);
let imageMessageTemplateBase = ptr(0);
let imageSendObjectTemplateBytes = null;
let imageMessageTemplateBytes = null;
let imageSendTemplateSummary = {};

function emit(type, extra) {
    send(Object.assign({type: type}, extra || {}));
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

function findExport(name) {
    try {
        if (typeof Module.findGlobalExportByName === 'function') {
            const p = Module.findGlobalExportByName(name);
            if (p) return p;
        }
    } catch (_) {}
    try {
        if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name);
    } catch (_) {}
    try {
        if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, name);
    } catch (_) {}
    return ptr(0);
}

function setupNativeAllocator() {
    const callocAddr = findExport('calloc');
    if (!callocAddr || callocAddr.isNull()) {
        emit('persistent_alloc_warning', {warning: 'calloc_not_found_falling_back_to_frida_heap'});
    } else {
        nativeCalloc = new NativeFunction(callocAddr, 'pointer', ['ulong', 'ulong']);
    }
    const freeAddr = findExport('free');
    if (freeAddr && !freeAddr.isNull()) nativeFree = new NativeFunction(freeAddr, 'void', ['pointer']);

    const mmapAddr = findExport('mmap');
    if (mmapAddr && !mmapAddr.isNull()) {
        nativeMmap = new NativeFunction(mmapAddr, 'pointer', ['pointer', 'ulong', 'int', 'int', 'int', 'long']);
    } else {
        emit('persistent_alloc_warning', {warning: 'mmap_not_found_falling_back_to_frida_code_heap'});
    }
    const munmapAddr = findExport('munmap');
    if (munmapAddr && !munmapAddr.isNull()) nativeMunmap = new NativeFunction(munmapAddr, 'int', ['pointer', 'ulong']);
}

function persistentAlloc(size, label) {
    if (nativeCalloc !== null) {
        const p = nativeCalloc(1, size);
        if (p.isNull()) throw new Error('calloc failed for ' + label + ' size=' + size);
        persistentAllocs.push({label: label, ptr: p.toString(), address: p, size: size, kind: 'calloc'});
        return p;
    }
    const p = Memory.alloc(size);
    persistentAllocs.push({label: label + ':frida_heap', ptr: p.toString(), address: p, size: size, kind: 'frida'});
    return p;
}

function isMmapFailed(p) {
    return !p || p.isNull() || p.toString() === '0xffffffffffffffff';
}

function persistentCodeAlloc(size, label) {
    if (nativeMmap !== null) {
        const PROT_READ = 1;
        const PROT_WRITE = 2;
        const PROT_EXEC = 4;
        const MAP_PRIVATE = 0x0002;
        const MAP_ANON = 0x1000;
        const MAP_JIT = 0x0800;
        let p = nativeMmap(ptr(0), size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
        if (isMmapFailed(p)) {
            p = nativeMmap(ptr(0), size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
        }
        if (!isMmapFailed(p)) {
            persistentAllocs.push({label: label + ':mmap_rwx', ptr: p.toString(), address: p, size: size, kind: 'mmap'});
            return p;
        }
        emit('persistent_alloc_warning', {warning: 'mmap_failed_falling_back_to_frida_code_heap', label: label});
    }
    const p = Memory.alloc(size);
    persistentAllocs.push({label: label + ':frida_code_heap', ptr: p.toString(), address: p, size: size, kind: 'frida'});
    return p;
}

function releasePersistentNativeAllocs(reason) {
    if (imageUploadEverTriggered) {
        emit('persistent_allocs_retained', {reason: reason, count: persistentAllocs.length});
        return 0;
    }
    let released = 0;
    for (let i = persistentAllocs.length - 1; i >= 0; i--) {
        const allocation = persistentAllocs[i];
        try {
            if (allocation.kind === 'calloc' && nativeFree !== null) {
                nativeFree(allocation.address);
                released += 1;
            } else if (allocation.kind === 'mmap' && nativeMunmap !== null) {
                nativeMunmap(allocation.address, allocation.size);
                released += 1;
            }
        } catch (e) {
            emit('persistent_alloc_release_error', {label: allocation.label, error: String(e)});
        }
    }
    persistentAllocs = persistentAllocs.filter(function (allocation) { return allocation.kind === 'frida'; });
    emit('persistent_allocs_released', {reason: reason, released: released, frida_owned: persistentAllocs.length});
    return released;
}

function readable(address) {
    try {
        if (!address || address.isNull()) return false;
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (_) {
        return false;
    }
}

function executable(address) {
    try {
        if (!address || address.isNull()) return false;
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf('x') !== -1;
    } catch (_) {
        return false;
    }
}

function readVtableSlot(vtable, slotOffset) {
    if (!readable(vtable.add(slotOffset))) return ptr(0);
    const fn = vtable.add(slotOffset).readPointer();
    return executable(fn) ? fn : ptr(0);
}

function readUtf8StringIfReadable(addr) {
    try {
        if (!readable(addr)) return '';
        return addr.readUtf8String();
    } catch (_) {
        return '';
    }
}

function inspectWechatString(addr) {
    try {
        if (!readable(addr.add(0x17))) return {readable: false, length: -1, text: ''};
        const tag = addr.add(0x17).readS8();
        let data = addr;
        let length = tag;
        if (tag < 0) {
            data = addr.readPointer();
            const rawLength = addr.add(0x08).readU64();
            length = Number(rawLength.toString());
        }
        let text = '';
        if (length > 0 && length <= 256 && readable(data)) {
            text = data.readUtf8String(length);
        }
        return {
            readable: true,
            heap: tag < 0,
            length: length,
            data: data.toString(),
            text: text,
        };
    } catch (e) {
        return {readable: false, length: -1, text: '', error: String(e)};
    }
}

function readByteArrayAsArray(addr, len) {
    const data = addr.readByteArray(len);
    return Array.from(new Uint8Array(data));
}

function writeByteArrayFromArray(addr, bytes) {
    addr.writeByteArray(bytes);
}

function ptrToBigInt(value) {
    try {
        if (typeof BigInt !== 'function') return null;
        return BigInt(value.toString());
    } catch (_) {
        return null;
    }
}

function makeRebaseMapping(src, dst, len, name) {
    const start = ptrToBigInt(src);
    return {
        src: src,
        dst: dst,
        len: len,
        name: name,
        start: start,
        end: start === null ? null : start + BigInt(len),
    };
}

function rebasePointersInClone(dst, len, mappings, label) {
    const counts = {};
    let patched = 0;
    let skipped = 0;
    for (let off = 0; off + Process.pointerSize <= len; off += Process.pointerSize) {
        let current = ptr(0);
        let currentValue = null;
        try {
            current = dst.add(off).readPointer();
            if (current.isNull()) continue;
            currentValue = ptrToBigInt(current);
            if (currentValue === null) {
                skipped += 1;
                continue;
            }
        } catch (_) {
            continue;
        }
        for (let i = 0; i < mappings.length; i++) {
            const m = mappings[i];
            if (m.start === null || m.end === null) continue;
            if (currentValue >= m.start && currentValue < m.end) {
                const delta = Number(currentValue - m.start);
                const replacement = m.dst.add(delta);
                dst.add(off).writePointer(replacement);
                counts[m.name] = (counts[m.name] || 0) + 1;
                patched += 1;
                break;
            }
        }
    }
    return {label: label, patched: patched, skipped: skipped, counts: counts};
}

function readPointerStringField(base, offset) {
    try {
        const p = base.add(offset).readPointer();
        return {ptr: p.toString(), text: readUtf8StringIfReadable(p)};
    } catch (e) {
        return {ptr: '0x0', text: '', error: String(e)};
    }
}

function summarizeUploadX1(x1) {
    const ptrFields = {};
    [0x00, 0x08, 0x48, 0xa8, 0xe8, 0x118, 0x148, 0x200].forEach(function (off) {
        ptrFields['0x' + off.toString(16)] = readPointerStringField(x1, off);
    });
    let receiverInline = '';
    try {
        receiverInline = x1.add(0x68).readUtf8String();
    } catch (_) {}
    return {
        x1: x1.toString(),
        ptr_fields: ptrFields,
        receiver_inline: receiverInline,
    };
}

function captureUploadTemplate(x1, reason) {
    if (uploadTemplateReady) return;
    if (!readable(x1) || ownsUploadX1(x1)) return;
    try {
        const func1 = x1.readPointer();
        const func2 = x1.add(0x08).readPointer();
        uploadTemplateBase = x1;
        uploadFunc1TemplateBase = func1;
        uploadFunc2TemplateBase = func2;
        uploadTemplateBytes = readByteArrayAsArray(x1, 0x2f8);
        uploadFunc1TemplateBytes = readable(func1) ? readByteArrayAsArray(func1, 24) : null;
        uploadFunc2TemplateBytes = readable(func2) ? readByteArrayAsArray(func2, 24) : null;
        uploadTemplateSummary = summarizeUploadX1(x1);
        uploadTemplateSummary.reason = reason;
        uploadTemplateSummary.func1_cloneable = uploadFunc1TemplateBytes !== null;
        uploadTemplateSummary.func2_cloneable = uploadFunc2TemplateBytes !== null;
        uploadTemplateReady = true;
        emit('upload_lifecycle_template_captured', uploadTemplateSummary);
    } catch (e) {
        emit('upload_lifecycle_template_error', {error: String(e), x1: x1.toString(), reason: reason});
    }
}

function captureUploadCallbackTemplate(table, reason) {
    if (uploadCallbackTemplateReady) return;
    if (!readable(table) || ownsUploadCallback(table) || table.equals(fakeVtable)) return;
    try {
        const getCallback = readVtableSlot(table, 0x10);
        const onComplete = readVtableSlot(table, 0x30);
        if (getCallback.isNull() && onComplete.isNull()) return;
        uploadCallbackTemplateBase = table;
        uploadCallbackTemplateBytes = readByteArrayAsArray(table, 0x100);
        uploadCallbackTemplateSummary = {
            table: table.toString(),
            reason: reason,
            get_callback_slot: getCallback.toString(),
            on_complete_slot: onComplete.toString(),
        };
        uploadCallbackTemplateReady = true;
        uploadCallbackTemplateApplied = false;
        emit('upload_callback_lifecycle_template_captured', uploadCallbackTemplateSummary);
    } catch (e) {
        emit('upload_callback_lifecycle_template_error', {error: String(e), table: table.toString(), reason: reason});
    }
}

function applyUploadCallbackTemplate(generation) {
    if (!uploadCallbackTemplateReady || uploadCallbackTemplateBytes === null) return false;
    if (!generation) return false;
    if (generation.callbackTemplateApplied) return true;
    const callbackTable = generation.uploadCallback;
    callbackTable.writeByteArray(uploadCallbackTemplateBytes);
    const rebaseSummary = rebasePointersInClone(
        callbackTable,
        uploadCallbackTemplateBytes.length,
        [makeRebaseMapping(uploadCallbackTemplateBase, callbackTable, uploadCallbackTemplateBytes.length, 'callback_table')],
        'uploadCallbackDispatchTable'
    );
    generation.callbackTemplateApplied = true;
    uploadCallbackTemplateApplied = true;
    emit('upload_callback_lifecycle_template_applied', {
        template_table: uploadCallbackTemplateBase.toString(),
        clone_table: callbackTable.toString(),
        generation_id: generation.id,
        rebase: rebaseSummary,
    });
    return true;
}

function initializeUploadCallbackDispatchTable(callbackTable) {
    /*
     * WeChat may invoke delayed lifecycle slots other than 0x10/0x30 after
     * upload_image_finish. A zero-filled synthetic table crashes with PC=0.
     * Point unknown slots at a persistent ret-one stub; patch the required
     * slots to real get_callback/on_complete handlers at wrapper time.
    */
    for (let i = 0; i < 32; i++) {
        callbackTable.add(i * Process.pointerSize).writePointer(retOneStub);
    }
}

function captureImageSendTemplateFromReq2Buf(ctx) {
    if (imageSendTemplateReady || sending) return;
    try {
        const base = ctx.x19;
        if (!readable(base.add(0x60))) return;
        const sendObj = base.add(0x60).readPointer();
        if (!readable(sendObj.add(0x28))) return;
        const msgObj = sendObj.add(0x28).readPointer();
        if (!readable(msgObj.add(0x20))) return;
        let cgi = '';
        try {
            cgi = readUtf8StringIfReadable(msgObj.add(0x18).readPointer());
        } catch (_) {}
        let msgType = 0;
        try {
            msgType = msgObj.add(0x0c).readU32();
        } catch (_) {}
        if (cgi.indexOf('/cgi-bin/micromsg-bin/uploadmsgimg') === -1 && msgType !== 0x6e) return;
        imageSendObjectTemplateBase = sendObj;
        imageMessageTemplateBase = msgObj;
        imageSendObjectTemplateBytes = readByteArrayAsArray(sendObj, 0x100);
        imageMessageTemplateBytes = readByteArrayAsArray(msgObj, 0x100);
        imageSendTemplateSummary = {
            send_object: sendObj.toString(),
            message_object: msgObj.toString(),
            cgi: cgi,
            msg_type: msgType,
            task_id: ctx.x1.toUInt32(),
            slot: base.add(0x60).toString(),
        };
        imageSendTemplateReady = true;
        emit('image_send_lifecycle_template_captured', imageSendTemplateSummary);
    } catch (e) {
        emit('image_send_lifecycle_template_error', {error: String(e)});
    }
}

function patchString(addr, plainStr) {
    addr.writeUtf8String(plainStr);
}

function utf8ByteLength(value) {
    let length = 0;
    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code <= 0x7f) {
            length += 1;
        } else if (code <= 0x7ff) {
            length += 2;
        } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length) {
            const low = value.charCodeAt(i + 1);
            if (low >= 0xdc00 && low <= 0xdfff) {
                length += 4;
                i += 1;
            } else {
                length += 3;
            }
        } else {
            length += 3;
        }
    }
    return length;
}

function patchUploadReceiver(objectAddr, backingAddr, receiver) {
    const length = utf8ByteLength(receiver);
    if (length >= 256) throw new Error('receiver_utf8_too_long_' + length);
    objectAddr.writeByteArray(new Array(24).fill(0));
    if (length <= 22) {
        objectAddr.writeUtf8String(receiver);
        objectAddr.add(23).writeU8(length);
        return {mode: 'short', length: length};
    }
    backingAddr.writeUtf8String(receiver);
    objectAddr.writePointer(backingAddr);
    objectAddr.add(8).writeU64(length);
    objectAddr.add(16).writeU64(uint64('0x8000000000000100'));
    return {mode: 'long', length: length};
}

function hexToByteArray(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) bytes.push(parseInt(hexStr.substr(i, 2), 16));
    return bytes;
}

function generateAESKey() {
    const chars = 'abcdef0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) key += chars.charAt(Math.floor(Math.random() * chars.length));
    return key;
}

function uploadReturnStatus(value) {
    const raw = value.toString();
    const parsed = Number(raw);
    let signed32 = null;
    if (Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 0xffffffff) {
        signed32 = parsed > 0x7fffffff ? parsed - 0x100000000 : parsed;
    } else if (Number.isSafeInteger(parsed) && parsed < 0) {
        signed32 = parsed;
    }
    return {raw: raw, signed32: signed32};
}

function setupRetOneStub() {
    retOneStub = persistentCodeAlloc(Process.pageSize, 'retOneStubPage');
    Memory.patchCode(retOneStub, 8, function (code) {
        code.writeByteArray([0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]);
    });
    fakeVtable = persistentAlloc(512, 'fakeVtable');
    for (let i = 0; i < 64; i++) fakeVtable.add(i * 8).writePointer(retOneStub);
}

function setupImageObjects() {
    imgCgiAddr = persistentAlloc(128, 'imgCgiAddr');
    imgProtoDataAddr = Memory.alloc(256 * 1024);

    patchString(imgCgiAddr, '/cgi-bin/micromsg-bin/uploadmsgimg');

    // Text and image share the same MMStartTask/Req2Buf/Buf2Resp hooks. Keep
    // both object families in this agent so a bot can alternate message types
    // without unloading or attaching a second Frida script.
    textCgiAddr = persistentAlloc(128, 'textCgiAddr');
    sendTextMessageAddr = persistentAlloc(256, 'sendTextMessageAddr');
    textMessageAddr = persistentAlloc(256, 'textMessageAddr');
    textProtoDataAddr = Memory.alloc(64 * 1024);
    textTriggerX1Payload = persistentAlloc(0x1a0, 'triggerTextTaskPayload');
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

function resetImageGeneration(generation) {
    const zero24 = new Array(24).fill(0);
    const zero256 = new Array(256).fill(0);
    generation.uploadFunc1Addr.writeByteArray(zero24);
    generation.uploadFunc2Addr.writeByteArray(zero24);
    generation.sendImgMessageAddr.writeByteArray(zero256);
    generation.imgMessageAddr.writeByteArray(zero256);
    initializeUploadCallbackDispatchTable(generation.uploadCallback);

    generation.fileId = '';
    generation.uploadAesKey = '';
    generation.taskId = 0;
    generation.uploadFinishedAt = 0;
    generation.retiredAt = 0;
    generation.retireReason = '';
    generation.callbackTemplateApplied = false;
    generation.allowStaticCallbackFallback = false;
    generation.forceStaticCallbackProfile = false;
    generation.uploadLifecycleTemplateMode = false;
    generation.uploadCallbackOverrideEnabled = true;

    generation.sendImgMessageAddr.add(0x00).writeU64(0);
    generation.sendImgMessageAddr.add(0x08).writeU64(0);
    generation.sendImgMessageAddr.add(0x10).writeU64(0);
    generation.sendImgMessageAddr.add(0x18).writeU64(1);
    generation.sendImgMessageAddr.add(0x20).writeU32(0);
    generation.sendImgMessageAddr.add(0x28).writePointer(generation.imgMessageAddr);

    generation.imgMessageAddr.add(0x00).writePointer(fakeVtable);
    generation.imgMessageAddr.add(0x08).writeU32(0);
    generation.imgMessageAddr.add(0x0c).writeU32(0x6e);
    generation.imgMessageAddr.add(0x10).writeU64(0x3);
    generation.imgMessageAddr.add(0x18).writePointer(imgCgiAddr);
    generation.imgMessageAddr.add(0x20).writeU64(0x22);
    generation.imgMessageAddr.add(0x28).writeU64(uint64('0x8000000000000030'));
    generation.imgMessageAddr.add(0x30).writeU64(uint64('0x0000000001010100'));
}

function createImageGeneration() {
    imageGenerationSequence += 1;
    const id = imageGenerationSequence;
    const prefix = 'imageGeneration[' + id + '].';
    const generation = {
        id: id,
        imageIdAddr: persistentAlloc(256, prefix + 'imageIdAddr'),
        md5Addr: persistentAlloc(256, prefix + 'md5Addr'),
        uploadAesKeyAddr: persistentAlloc(256, prefix + 'uploadAesKeyAddr'),
        uploadReceiverAddr: persistentAlloc(256, prefix + 'uploadReceiverAddr'),
        imagePathAddr: persistentAlloc(1024, prefix + 'imagePathAddr'),
        uploadImageX1: persistentAlloc(2048, prefix + 'uploadImageX1'),
        uploadFunc1Addr: persistentAlloc(24, prefix + 'uploadFunc1Addr'),
        uploadFunc2Addr: persistentAlloc(24, prefix + 'uploadFunc2Addr'),
        uploadCallback: persistentAlloc(256, prefix + 'uploadCallback'),
        sendImgMessageAddr: persistentAlloc(256, prefix + 'sendImgMessageAddr'),
        imgMessageAddr: persistentAlloc(256, prefix + 'imgMessageAddr'),
        triggerX1Payload: persistentAlloc(0x1a0, prefix + 'triggerImageTaskPayload'),
    };
    resetImageGeneration(generation);
    imageGenerations.push(generation);
    return generation;
}

function activateImageGeneration(generation) {
    activeImageGeneration = generation;
    imageIdAddr = generation.imageIdAddr;
    md5Addr = generation.md5Addr;
    uploadAesKeyAddr = generation.uploadAesKeyAddr;
    imagePathAddr = generation.imagePathAddr;
    uploadImageX1 = generation.uploadImageX1;
    uploadFunc1Addr = generation.uploadFunc1Addr;
    uploadFunc2Addr = generation.uploadFunc2Addr;
    uploadCallback = generation.uploadCallback;
    sendImgMessageAddr = generation.sendImgMessageAddr;
    imgMessageAddr = generation.imgMessageAddr;
    triggerX1Payload = generation.triggerX1Payload;
}

function acquireImageGeneration() {
    const now = Date.now();
    let generation = null;
    for (let i = 0; i < imageGenerations.length; i++) {
        const candidate = imageGenerations[i];
        if (candidate.retiredAt > 0 && now - candidate.retiredAt >= imageGenerationRetentionMs) {
            generation = candidate;
            break;
        }
    }
    const reused = generation !== null;
    if (generation === null) generation = createImageGeneration();
    else resetImageGeneration(generation);
    activateImageGeneration(generation);
    emit('image_generation_acquired', {
        generation_id: generation.id,
        reused: reused,
        pool_size: imageGenerations.length,
        retention_ms: imageGenerationRetentionMs,
    });
    return generation;
}

function retireActiveImageGeneration(reason) {
    if (activeImageGeneration === null) return false;
    activeImageGeneration.retiredAt = Date.now();
    activeImageGeneration.retireReason = reason || 'unknown';
    emit('image_generation_retired', {
        generation_id: activeImageGeneration.id,
        file_id: activeImageGeneration.fileId,
        task_id: activeImageGeneration.taskId,
        reason: activeImageGeneration.retireReason,
        pool_size: imageGenerations.length,
    });
    activeImageGeneration = null;
    return true;
}

function findImageGenerationByFileId(fileId) {
    if (!fileId) return null;
    for (let i = imageGenerations.length - 1; i >= 0; i--) {
        if (imageGenerations[i].fileId === fileId) return imageGenerations[i];
    }
    return null;
}

function ownsUploadX1(address) {
    for (let i = 0; i < imageGenerations.length; i++) {
        if (imageGenerations[i].uploadImageX1.equals(address)) return true;
    }
    return false;
}

function ownsUploadCallback(address) {
    for (let i = 0; i < imageGenerations.length; i++) {
        if (imageGenerations[i].uploadCallback.equals(address)) return true;
    }
    return false;
}

function configureGenerationRetention(seconds) {
    const parsed = Number(seconds);
    if (!Number.isFinite(parsed) || parsed < 0) return {ok: false, error: 'invalid_retention_seconds'};
    imageGenerationRetentionMs = Math.max(1000, Math.floor(parsed * 1000));
    emit('image_generation_retention_configured', {retention_ms: imageGenerationRetentionMs});
    return {ok: true, retention_ms: imageGenerationRetentionMs};
}

function callbacksReady() {
    return !learnedGetCallbackFunc.isNull() && !learnedOnCompleteFunc.isNull();
}

function clearInserted(reason, strategy) {
    if (!inserted || insertedAddr.isNull()) return false;
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

function detachAllHooks(reason) {
    if (hooksDetached) return false;
    try {
        uploadHookListeners = [];
        Interceptor.detachAll();
        hooksDetached = true;
        emit('hooks_detached', {reason: reason || 'manual'});
        return true;
    } catch (e) {
        emit('hooks_detach_error', {reason: reason || 'manual', error: String(e)});
        return false;
    }
}

function attachUploadHook(name, address, callbacks) {
    const listener = Interceptor.attach(address, callbacks);
    uploadHookListeners.push({name: name, listener: listener});
    return listener;
}

function detachUploadHooks(reason) {
    if (uploadHookListeners.length === 0) return false;
    const names = [];
    while (uploadHookListeners.length > 0) {
        const item = uploadHookListeners.pop();
        try {
            item.listener.detach();
            names.push(item.name);
        } catch (e) {
            emit('upload_hook_detach_error', {reason: reason || 'manual', name: item.name, error: String(e)});
        }
    }
    emit('upload_hooks_detached', {reason: reason || 'manual', names: names});
    return names.length > 0;
}

function configureCleanup(autoDetachAfterAck, autoDetachUploadAfterFinish) {
    autoDetachHooksAfterAck = !!autoDetachAfterAck;
    autoDetachUploadHooksAfterFinish = !!autoDetachUploadAfterFinish;
    emit('cleanup_policy_configured', {
        auto_detach_hooks_after_ack: autoDetachHooksAfterAck,
        auto_detach_upload_hooks_after_finish: autoDetachUploadHooksAfterFinish,
        model: autoDetachHooksAfterAck || autoDetachUploadHooksAfterFinish ? 'agent_auto_detach' : 'host_drain_then_force_cleanup',
    });
    return {
        ok: true,
        auto_detach_hooks_after_ack: autoDetachHooksAfterAck,
        auto_detach_upload_hooks_after_finish: autoDetachUploadHooksAfterFinish,
    };
}

function attachHooks(module) {
    const sendFuncAddr = module.base.add(OFFSETS.sendFuncAddr);
    const sendHookAddr = sendFuncAddr.add(OFFSETS.sendFuncHookDelta);
    const defaultStartTaskFuncAddr = module.base.add(OFFSETS.defaultStartTaskFuncAddr);
    const req2bufEnterAddr = module.base.add(OFFSETS.req2bufEnterHookAddr);
    const req2bufExitAddr = module.base.add(OFFSETS.req2bufExitHookAddr);
    const blrX8Addr = module.base.add(OFFSETS.blrX8HookAddr);
    const autoBufferWriteAddr = module.base.add(OFFSETS.autoBufferWriteFunc);
    const buf2RespAckAddr = module.base.add(OFFSETS.buf2RespAckHookAddr);
    const logBuf2RespAddr = module.base.add(OFFSETS.logBuf2RespHookAddr);
    const uploadImageAddr = module.base.add(OFFSETS.uploadImageAddr);
    const uploadImageEntryWrapperAddr = module.base.add(OFFSETS.uploadImageEntryWrapperAddr);
    const cndOnCompleteAddr = module.base.add(OFFSETS.cndOnCompleteAddr);
    const uploadGetCallbackWrapperAddr = module.base.add(OFFSETS.uploadGetCallbackWrapperAddr);
    const uploadGetCallbackWrapperFuncAddr = module.base.add(OFFSETS.uploadGetCallbackWrapperFuncAddr);
    const uploadOnCompleteAddr = module.base.add(OFFSETS.uploadOnCompleteAddr);
    const uploadOnCompleteFuncAddr = module.base.add(OFFSETS.uploadOnCompleteFuncAddr);
    const uploadRsaPreflightAddr = module.base.add(OFFSETS.uploadRsaPreflightAddr);

    sendFunc = new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);
    defaultStartTaskFunc = new NativeFunction(defaultStartTaskFuncAddr, 'int64', ['pointer']);
    uploadImageFunc = new NativeFunction(uploadImageAddr, 'int64', ['pointer', 'pointer']);
    uploadImageEntryWrapperFunc = new NativeFunction(uploadImageEntryWrapperAddr, 'int64', ['pointer']);
    nativeAutoBufferWrite = new NativeFunction(autoBufferWriteAddr, 'int', ['pointer', 'pointer', 'int']);

    Interceptor.attach(sendHookAddr, {
        onEnter: function () {
            if (!contextReady) {
                triggerX0 = this.context.x0;
                contextReady = true;
                emit('context_captured', {x0: triggerX0.toString(), x1: this.context.x1.toString()});
            }
        },
    });

    attachUploadHook('upload_context', uploadImageAddr.add(0x10), {
        onEnter: function () {
            captureUploadTemplate(this.context.x1, 'uploadImage+0x10');
            if (!uploadContextReady) {
                uploadGlobalX0 = this.context.x0;
                uploadContextReady = true;
                emit('upload_context_captured', {x0: uploadGlobalX0.toString(), x1: this.context.x1.toString()});
            }
        },
    });

    attachUploadHook('upload_rsa_preflight', uploadRsaPreflightAddr, {
        onEnter: function () {
            const request = this.context.x20;
            if (!ownsUploadX1(request)) return;
            let managerState = ptr(0);
            try {
                if (readable(this.context.x19.add(0x08))) managerState = this.context.x19.add(0x08).readPointer();
            } catch (_) {}
            emit('upload_preflight_probe', {
                check: 'manager_rsa',
                generation_id: activeImageGeneration === null ? 0 : activeImageGeneration.id,
                result: this.context.x21.toInt32(),
                request: request.toString(),
                manager: this.context.x19.toString(),
                manager_state: managerState.toString(),
                rsa_b8: managerState.isNull() ? null : inspectWechatString(managerState.add(0xb8)),
                rsa_d0: managerState.isNull() ? null : inspectWechatString(managerState.add(0xd0)),
                rsa_e8: managerState.isNull() ? null : inspectWechatString(managerState.add(0xe8)),
            });
        },
    });

    Interceptor.attach(req2bufEnterAddr, {
        onEnter: function () {
            captureImageSendTemplateFromReq2Buf(this.context);
            if (!sending || taskIdGlobal === 0 || !this.context.x1.equals(ptr(taskIdGlobal))) return;
            const base = this.context.x19;
            if (!readable(base.add(0x60))) {
                emit('req2buf_insert_error', {error: 'base+0x60 unreadable', base: base.toString()});
                return;
            }
            const targetAddr = base.add(0x60);
            const replacement = sendMsgType === 'text' ? sendTextMessageAddr : sendImgMessageAddr;
            const currentValue = targetAddr.readPointer();
            if (inserted && !insertedAddr.isNull() && targetAddr.equals(insertedAddr)) {
                if (currentValue.equals(replacement)) {
                    emit('req2buf_reentered', {
                        task_id: taskIdGlobal,
                        base: base.toString(),
                        address: targetAddr.toString(),
                        preserved_original: insertedOriginal.toString(),
                        replacement: replacement.toString(),
                        msg_type: sendMsgType,
                    });
                    return;
                }
            } else if (inserted && !insertedAddr.isNull() && !targetAddr.equals(insertedAddr)) {
                clearInserted('req2buf_reentry_new_address', 'null');
            }
            insertedAddr = targetAddr;
            insertedOriginal = currentValue;
            insertedAddr.writePointer(replacement);
            inserted = true;
            emit('req2buf_inserted', {
                task_id: taskIdGlobal,
                base: base.toString(),
                address: insertedAddr.toString(),
                original: insertedOriginal.toString(),
                replacement: replacement.toString(),
                msg_type: sendMsgType,
            });
        },
    });

    Interceptor.attach(blrX8Addr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || this.context.x20.toUInt32() !== taskIdGlobal) return;
            if (!imgProtoHexGlobal || imgProtoHexGlobal.length === 0) {
                emit('protobuf_error', {error: 'empty proto hex', msg_type: sendMsgType});
                return;
            }
            const finalPayload = hexToByteArray(imgProtoHexGlobal);
            const protoDataAddr = sendMsgType === 'text' ? textProtoDataAddr : imgProtoDataAddr;
            protoDataAddr.writeByteArray(finalPayload);
            const autoBuffer = this.context.sp.add(0x140);
            nativeAutoBufferWrite(autoBuffer, protoDataAddr, finalPayload.length);
            this.context.x8 = retOneStub;
            protoWritten = true;
            emit('protobuf_written', {task_id: taskIdGlobal, msg_type: sendMsgType, length: finalPayload.length, auto_buffer: autoBuffer.toString()});
        },
    });

    Interceptor.attach(req2bufExitAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || !inserted) return;
            emit('req2buf_exit_pending_ack', {task_id: taskIdGlobal, inserted_address: insertedAddr.toString()});
        },
    });

    Interceptor.attach(logBuf2RespAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0 || !this.context.x1.equals(ptr(taskIdGlobal))) return;
            logBuf2RespSeen = true;
            emit('log_buf2resp_seen', {task_id: taskIdGlobal, x0: this.context.x0.toString(), x1: this.context.x1.toString()});
        },
    });

    Interceptor.attach(buf2RespAckAddr, {
        onEnter: function () {
            if (!sending || taskIdGlobal === 0) return;
            let respTaskId = 0;
            let responseLen = -1;
            try {
                respTaskId = this.context.sp.add(0x140).readS32();
                responseLen = this.context.x0.toInt32();
            } catch (e) {
                ackReadErrors += 1;
                if (ackReadErrors <= 3) emit('buf2resp_ack_probe_error', {error: String(e)});
                return;
            }
            if (respTaskId !== taskIdGlobal) return;
            ackSeen = true;
            const finishedMessageType = sendMsgType;
            emit('buf2resp_ack', {
                task_id: taskIdGlobal,
                msg_type: finishedMessageType,
                response_len: responseLen,
                response_ptr: this.context.x20.toString(),
                sp_task_id_addr: this.context.sp.add(0x140).toString(),
            });
            clearInserted('buf2resp_ack', 'null');
            const finishedTaskId = taskIdGlobal;
            sending = false;
            if (finishedMessageType === 'img') retireActiveImageGeneration('buf2resp_ack');
            emit('finish', {task_id: finishedTaskId, msg_type: finishedMessageType, inserted: inserted, proto_written: protoWritten, log_buf2resp_seen: logBuf2RespSeen, ack_seen: ackSeen});
            taskIdGlobal = 0;
            sendMsgType = '';
            if (autoDetachHooksAfterAck) {
                setTimeout(function () {
                    detachAllHooks('finish_after_ack');
                }, 500);
            } else {
                emit('hooks_retained_after_finish', {
                    reason: 'finish_after_ack',
                    until: 'host_force_cleanup_after_drain',
                    upload_hook_count: uploadHookListeners.length,
                });
            }
        },
    });

    attachUploadHook('upload_get_callback_wrapper', uploadGetCallbackWrapperAddr, {
        onEnter: function () {
            try {
                const tmpFileId = this.context.x1.readPointer().readUtf8String();
                const generation = findImageGenerationByFileId(tmpFileId);
                const isTarget = generation !== null;
                const imageFileId = isTarget ? generation.fileId : '';
                const originalTable = this.context.x8;
                captureUploadCallbackTemplate(originalTable, isTarget ? 'target_get_callback_wrapper_before_patch' : 'get_callback_wrapper');
                const originalFunc = readVtableSlot(originalTable, 0x10);
                if (!isTarget && !originalFunc.isNull() && !originalFunc.equals(learnedGetCallbackFunc)) {
                    learnedGetCallbackFunc = originalFunc;
                    learnedGetCallbackSamples += 1;
                    emit('upload_callback_method_captured', {
                        slot: 'get_callback',
                        func: learnedGetCallbackFunc.toString(),
                        samples: learnedGetCallbackSamples,
                    });
                }
                if (!isTarget) return;
                if (generation.uploadLifecycleTemplateMode && !generation.uploadCallbackOverrideEnabled) {
                    emit('upload_callback_wrapper_bypassed', {
                        file_id: imageFileId,
                        generation_id: generation.id,
                        reason: 'real_lifecycle_template_keeps_original_x8',
                        x8: this.context.x8.toString(),
                        original_slot: originalFunc.toString(),
                    });
                    return;
                }
                const staticFunc = generation.allowStaticCallbackFallback ? uploadGetCallbackWrapperFuncAddr : ptr(0);
                const patchFunc = generation.forceStaticCallbackProfile ? staticFunc : (!learnedGetCallbackFunc.isNull() ? learnedGetCallbackFunc : staticFunc);
                if (patchFunc.isNull()) {
                    emit('upload_callback_wrapper_blocked', {file_id: imageFileId, generation_id: generation.id, reason: generation.forceStaticCallbackProfile ? 'static_get_callback_profile_not_allowed' : 'get_callback_method_not_ready'});
                    return;
                }
                applyUploadCallbackTemplate(generation);
                generation.uploadCallback.add(0x10).writePointer(patchFunc);
                this.context.x8 = generation.uploadCallback;
                emit('upload_callback_wrapper_patched', {
                    file_id: imageFileId,
                    generation_id: generation.id,
                    func: patchFunc.toString(),
                    dynamic: !generation.forceStaticCallbackProfile && patchFunc.equals(learnedGetCallbackFunc),
                    static_profile: generation.forceStaticCallbackProfile,
                    original_table: originalTable.toString(),
                    original_slot: originalFunc.toString(),
                    lifecycle_template: generation.callbackTemplateApplied,
                });
            } catch (e) {
                emit('upload_callback_wrapper_error', {error: String(e)});
            }
        },
    });

    attachUploadHook('upload_on_complete_wrapper', uploadOnCompleteAddr, {
        onEnter: function () {
            try {
                const tmpFileId = this.context.x1.readPointer().readUtf8String();
                const generation = findImageGenerationByFileId(tmpFileId);
                const isTarget = generation !== null;
                const imageFileId = isTarget ? generation.fileId : '';
                const originalTable = this.context.x8;
                captureUploadCallbackTemplate(originalTable, isTarget ? 'target_on_complete_wrapper_before_patch' : 'on_complete_wrapper');
                const originalFunc = readVtableSlot(originalTable, 0x30);
                if (!isTarget && !originalFunc.isNull() && !originalFunc.equals(learnedOnCompleteFunc)) {
                    learnedOnCompleteFunc = originalFunc;
                    learnedOnCompleteSamples += 1;
                    emit('upload_callback_method_captured', {
                        slot: 'on_complete',
                        func: learnedOnCompleteFunc.toString(),
                        samples: learnedOnCompleteSamples,
                    });
                }
                if (!isTarget) return;
                if (generation.uploadLifecycleTemplateMode && !generation.uploadCallbackOverrideEnabled) {
                    emit('upload_oncomplete_bypassed', {
                        file_id: imageFileId,
                        generation_id: generation.id,
                        reason: 'real_lifecycle_template_keeps_original_x8',
                        x8: this.context.x8.toString(),
                        original_slot: originalFunc.toString(),
                    });
                    return;
                }
                const staticFunc = generation.allowStaticCallbackFallback ? uploadOnCompleteFuncAddr : ptr(0);
                const patchFunc = generation.forceStaticCallbackProfile ? staticFunc : (!learnedOnCompleteFunc.isNull() ? learnedOnCompleteFunc : staticFunc);
                if (patchFunc.isNull()) {
                    emit('upload_oncomplete_blocked', {file_id: imageFileId, generation_id: generation.id, reason: generation.forceStaticCallbackProfile ? 'static_on_complete_profile_not_allowed' : 'on_complete_method_not_ready'});
                    return;
                }
                applyUploadCallbackTemplate(generation);
                generation.uploadCallback.add(0x30).writePointer(patchFunc);
                this.context.x8 = generation.uploadCallback;
                emit('upload_oncomplete_patched', {
                    file_id: imageFileId,
                    generation_id: generation.id,
                    func: patchFunc.toString(),
                    dynamic: !generation.forceStaticCallbackProfile && patchFunc.equals(learnedOnCompleteFunc),
                    static_profile: generation.forceStaticCallbackProfile,
                    original_table: originalTable.toString(),
                    original_slot: originalFunc.toString(),
                    lifecycle_template: generation.callbackTemplateApplied,
                });
            } catch (e) {
                emit('upload_oncomplete_error', {error: String(e)});
            }
        },
    });

    attachUploadHook('cdn_on_complete', cndOnCompleteAddr, {
        onEnter: function () {
            try {
                const x2 = this.context.x2;
                if (!readable(x2.add(0x20))) return;
                const filePtr = x2.add(0x20).readPointer();
                const currentFileId = readUtf8StringIfReadable(filePtr);
                const generation = findImageGenerationByFileId(currentFileId);
                if (generation === null) return;

                const cdnKey = readUtf8StringIfReadable(x2.add(0x60).readPointer());
                const aesKey = readUtf8StringIfReadable(x2.add(0x78).readPointer());
                const md5Key = readUtf8StringIfReadable(x2.add(0x90).readPointer());
                const targetId = x2.add(0x40).readUtf8String();
                if (!cdnKey || !aesKey) {
                    // Identical-image deduplication can return an old CDN object
                    // without its old AES key. The new request key is not a safe
                    // substitute. Keep waiting and let the host report a clear
                    // timeout; normal sends salt the staged copy to avoid this
                    // branch in the first place.
                    emit('upload_image_incomplete', {
                        target_id: targetId,
                        file_id: currentFileId,
                        generation_id: generation.id,
                        cdn_key_length: cdnKey.length,
                        aes_key_length: aesKey.length,
                        md5_key: md5Key,
                    });
                    return;
                }
                generation.uploadFinishedAt = Date.now();
                emit('upload_image_finish', {
                    target_id: targetId,
                    file_id: currentFileId,
                    generation_id: generation.id,
                    cdn_key: cdnKey,
                    aes_key: aesKey,
                    aes_key_source: 'callback',
                    aes_key_matches_request: aesKey === generation.uploadAesKey,
                    md5_key: md5Key,
                });
                if (autoDetachUploadHooksAfterFinish) {
                    setTimeout(function () {
                        detachUploadHooks('upload_image_finish');
                    }, 500);
                } else {
                    emit('upload_hooks_retained', {
                        reason: 'upload_image_finish',
                        until: 'host_force_cleanup_after_drain',
                        upload_hook_count: uploadHookListeners.length,
                    });
                }
            } catch (e) {
                emit('upload_finish_error', {error: String(e)});
            }
        },
    });

    return {
        sendFuncAddr: sendFuncAddr.toString(),
        sendHookAddr: sendHookAddr.toString(),
        defaultStartTaskFuncAddr: defaultStartTaskFuncAddr.toString(),
        req2bufEnterAddr: req2bufEnterAddr.toString(),
        req2bufExitAddr: req2bufExitAddr.toString(),
        blrX8Addr: blrX8Addr.toString(),
        autoBufferWriteFunc: autoBufferWriteAddr.toString(),
        buf2RespAckHookAddr: buf2RespAckAddr.toString(),
        logBuf2RespHookAddr: logBuf2RespAddr.toString(),
        uploadImageAddr: uploadImageAddr.toString(),
        uploadHookAddr: uploadImageAddr.add(0x10).toString(),
        uploadImageEntryWrapperAddr: uploadImageEntryWrapperAddr.toString(),
        cndOnCompleteAddr: cndOnCompleteAddr.toString(),
        uploadGetCallbackWrapperAddr: uploadGetCallbackWrapperAddr.toString(),
        uploadGetCallbackWrapperFuncAddr: uploadGetCallbackWrapperFuncAddr.toString(),
        uploadOnCompleteAddr: uploadOnCompleteAddr.toString(),
        uploadOnCompleteFuncAddr: uploadOnCompleteFuncAddr.toString(),
        uploadRsaPreflightAddr: uploadRsaPreflightAddr.toString(),
        instructions: {
            send: Instruction.parse(sendFuncAddr).toString(),
            send_hook: Instruction.parse(sendHookAddr).toString(),
            default_start_task: Instruction.parse(defaultStartTaskFuncAddr).toString(),
            req2buf_enter: Instruction.parse(req2bufEnterAddr).toString(),
            blr_x8: Instruction.parse(blrX8Addr).toString(),
            auto_buffer_write: Instruction.parse(autoBufferWriteAddr).toString(),
            buf2resp_ack: Instruction.parse(buf2RespAckAddr).toString(),
            upload: Instruction.parse(uploadImageAddr).toString(),
            upload_hook: Instruction.parse(uploadImageAddr.add(0x10)).toString(),
            upload_entry_wrapper: Instruction.parse(uploadImageEntryWrapperAddr).toString(),
            cdn_on_complete: Instruction.parse(cndOnCompleteAddr).toString(),
            upload_get_cb: Instruction.parse(uploadGetCallbackWrapperAddr).toString(),
            upload_on_complete: Instruction.parse(uploadOnCompleteAddr).toString(),
            upload_rsa_preflight: Instruction.parse(uploadRsaPreflightAddr).toString(),
        },
    };
}

function triggerUploadImage(receiver, md5, imagePath, payloadHex, allowStaticCallbacks, useLifecycleTemplate, forceStaticCallbacks, useEntryWrapper) {
    const proactiveEntryWrapper = !!useEntryWrapper;
    if (!proactiveEntryWrapper && (!uploadContextReady || uploadGlobalX0.isNull())) return {ok: false, error: 'upload_context_not_ready'};
    if (activeImageGeneration !== null) {
        return {
            ok: false,
            error: 'image_generation_busy',
            generation_id: activeImageGeneration.id,
            file_id: activeImageGeneration.fileId,
            task_id: activeImageGeneration.taskId,
        };
    }
    allowStaticCallbackFallback = !!allowStaticCallbacks;
    forceStaticCallbackProfile = !!forceStaticCallbacks;
    uploadLifecycleTemplateMode = !!useLifecycleTemplate;
    uploadCallbackOverrideEnabled = !uploadLifecycleTemplateMode;
    uploadCallbackTemplateApplied = false;
    if (!callbacksReady() && !allowStaticCallbackFallback) {
        return {
            ok: false,
            error: 'callback_methods_not_ready',
            learned_get_callback_func: learnedGetCallbackFunc.toString(),
            learned_on_complete_func: learnedOnCompleteFunc.toString(),
            hint: 'manually_send_one_small_image_to_filehelper_before_trigger',
        };
    }
    const useTemplate = !!useLifecycleTemplate;
    if (useTemplate && !uploadTemplateReady) {
        return {ok: false, error: 'upload_lifecycle_template_not_ready'};
    }
    if (useTemplate && !uploadCallbackTemplateReady) return {ok: false, error: 'upload_callback_lifecycle_template_not_ready'};
    const payload = useTemplate ? uploadTemplateBytes : hexToByteArray(payloadHex);
    if (payload.length !== 0x2f8) return {ok: false, error: 'bad_upload_payload_len_' + payload.length};
    const generation = acquireImageGeneration();
    generation.allowStaticCallbackFallback = allowStaticCallbackFallback;
    generation.forceStaticCallbackProfile = forceStaticCallbackProfile;
    generation.uploadLifecycleTemplateMode = uploadLifecycleTemplateMode;
    generation.uploadCallbackOverrideEnabled = uploadCallbackOverrideEnabled;
    // The live-validated synthetic upload object is fragile: it expects the
    // same short-string layout used by the original test harness. Do not patch
    // the adjacent libc++ length words here; writing dynamic lengths caused
    // StartC2CUpload to reject the object with -20003 on 4.1.11.54.
    imageUploadSequence += 1;
    const fileId = receiver + '_' + String(Math.floor(Date.now() / 1000)) + '_' + Math.floor(Math.random() * 1001) + '_1';
    generation.fileId = fileId;
    patchString(imageIdAddr, fileId);
    patchString(md5Addr, md5);
    generation.uploadAesKey = generateAESKey();
    patchString(uploadAesKeyAddr, generation.uploadAesKey);
    patchString(imagePathAddr, imagePath);

    let uploadRebaseSummary = null;
    let uploadFunc1RebaseSummary = null;
    let uploadFunc2RebaseSummary = null;
    uploadImageX1.writeByteArray(payload);
    if (useTemplate) {
        if (uploadFunc1TemplateBytes !== null) uploadFunc1Addr.writeByteArray(uploadFunc1TemplateBytes);
        if (uploadFunc2TemplateBytes !== null) uploadFunc2Addr.writeByteArray(uploadFunc2TemplateBytes);
        const uploadMappings = [makeRebaseMapping(uploadTemplateBase, uploadImageX1, uploadTemplateBytes.length, 'upload_x1')];
        if (uploadFunc1TemplateBytes !== null) uploadMappings.push(makeRebaseMapping(uploadFunc1TemplateBase, uploadFunc1Addr, uploadFunc1TemplateBytes.length, 'upload_func1'));
        if (uploadFunc2TemplateBytes !== null) uploadMappings.push(makeRebaseMapping(uploadFunc2TemplateBase, uploadFunc2Addr, uploadFunc2TemplateBytes.length, 'upload_func2'));
        uploadRebaseSummary = rebasePointersInClone(uploadImageX1, payload.length, uploadMappings, 'uploadX1');
        if (uploadFunc1TemplateBytes !== null) uploadFunc1RebaseSummary = rebasePointersInClone(uploadFunc1Addr, uploadFunc1TemplateBytes.length, uploadMappings, 'uploadFunc1');
        if (uploadFunc2TemplateBytes !== null) uploadFunc2RebaseSummary = rebasePointersInClone(uploadFunc2Addr, uploadFunc2TemplateBytes.length, uploadMappings, 'uploadFunc2');
        if (uploadCallbackOverrideEnabled) applyUploadCallbackTemplate(generation);
    }
    uploadImageX1.writePointer(uploadFunc1Addr);
    uploadImageX1.add(0x08).writePointer(uploadFunc2Addr);
    uploadImageX1.add(0x48).writePointer(imageIdAddr);
    uploadImageX1.add(0x68).writeUtf8String(receiver);
    uploadImageX1.add(0xa8).writePointer(md5Addr);
    uploadImageX1.add(0xe8).writePointer(imagePathAddr);
    uploadImageX1.add(0x118).writePointer(imagePathAddr);
    uploadImageX1.add(0x148).writePointer(imagePathAddr);
    uploadImageX1.add(0x200).writePointer(uploadAesKeyAddr);

    emit('upload_triggering', {
        receiver: receiver,
        file_id: fileId,
        file_id_length: fileId.length,
        receiver_utf8_length: utf8ByteLength(receiver),
        receiver_string_mode: 'inline_static_profile',
        path_utf8_length: utf8ByteLength(imagePath),
        generation_id: generation.id,
        path: imagePath,
        md5: md5,
        x0: uploadGlobalX0.toString(),
        x1: uploadImageX1.toString(),
        proactive_entry_wrapper: proactiveEntryWrapper,
        entry_wrapper: uploadImageEntryWrapperFunc === null ? '0x0' : module.base.add(OFFSETS.uploadImageEntryWrapperAddr).toString(),
        lifecycle_template: useTemplate,
        upload_rebase: uploadRebaseSummary,
        upload_func1_rebase: uploadFunc1RebaseSummary,
        upload_func2_rebase: uploadFunc2RebaseSummary,
        callback_template: uploadCallbackTemplateReady,
        callback_override: uploadCallbackOverrideEnabled,
        callback_table_mode: uploadCallbackTemplateReady ? 'cloned_template' : 'ret_one_plus_required_slots',
        force_static_callback_profile: forceStaticCallbackProfile,
        func1_template_cloned: useTemplate && uploadFunc1TemplateBytes !== null,
        func2_template_cloned: useTemplate && uploadFunc2TemplateBytes !== null,
    });
    try {
        imageUploadEverTriggered = true;
        const rv = proactiveEntryWrapper ? uploadImageEntryWrapperFunc(uploadImageX1) : uploadImageFunc(uploadGlobalX0, uploadImageX1);
        const returnStatus = uploadReturnStatus(rv);
        emit('upload_trigger_returned', {
            return_value: returnStatus.raw,
            return_value_signed32: returnStatus.signed32,
            file_id: fileId,
            generation_id: generation.id,
            path: imagePath,
        });
        if (returnStatus.signed32 !== null && returnStatus.signed32 < 0) {
            emit('upload_trigger_rejected', {
                return_value: returnStatus.raw,
                return_value_signed32: returnStatus.signed32,
                file_id: fileId,
                generation_id: generation.id,
                path: imagePath,
            });
            retireActiveImageGeneration('upload_entry_rejected');
            return {
                ok: false,
                error: 'upload_entry_rejected_' + returnStatus.signed32,
                return_value: returnStatus.raw,
                return_value_signed32: returnStatus.signed32,
                file_id: fileId,
                generation_id: generation.id,
                path: imagePath,
            };
        }
        return {
            ok: true,
            return_value: returnStatus.raw,
            return_value_signed32: returnStatus.signed32,
            file_id: fileId,
            generation_id: generation.id,
            path: imagePath,
        };
    } catch (e) {
        emit('upload_trigger_error', {error: String(e), file_id: fileId, generation_id: generation.id});
        retireActiveImageGeneration('upload_trigger_error');
        return {ok: false, error: String(e)};
    }
}

function triggerSendText(taskId, protoHex, payloadHex) {
    if (defaultStartTaskFunc === null && (!contextReady || triggerX0.isNull())) {
        return {ok: false, error: 'start_task_dispatch_not_ready'};
    }
    if (sending) return {ok: false, error: 'already_sending'};
    if (!taskId || taskId <= 0) return {ok: false, error: 'bad_task_id'};
    const payloadBytes = hexToByteArray(payloadHex);
    if (payloadBytes.length !== 0x1a0) return {ok: false, error: 'bad_payload_len_' + payloadBytes.length};

    taskIdGlobal = taskId >>> 0;
    imgProtoHexGlobal = protoHex;
    sendMsgType = 'text';
    inserted = false;
    protoWritten = false;
    cleanupDone = false;
    logBuf2RespSeen = false;
    ackSeen = false;
    ackReadErrors = 0;

    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);
    textTriggerX1Payload.writeByteArray(payloadBytes);
    textTriggerX1Payload.add(0x18).writePointer(textCgiAddr);
    textTriggerX1Payload.add(0xb8).writePointer(textTriggerX1Payload.add(0xc0));
    textTriggerX1Payload.add(0x190).writePointer(textTriggerX1Payload.add(0x198));

    sending = true;
    const dispatchMode = defaultStartTaskFunc !== null ? 'default_manager_wrapper' : 'captured_context';
    emit('triggering', {
        task_id: taskIdGlobal,
        msg_type: 'text',
        x0: triggerX0.toString(),
        x1: textTriggerX1Payload.toString(),
        proto_len: protoHex.length / 2,
        dispatch_mode: dispatchMode,
    });
    try {
        const rv = defaultStartTaskFunc !== null
            ? defaultStartTaskFunc(textTriggerX1Payload)
            : sendFunc(triggerX0, textTriggerX1Payload);
        const returnValue = rv.toString();
        emit('trigger_returned', {task_id: taskIdGlobal, msg_type: 'text', return_value: returnValue, dispatch_mode: dispatchMode});
        if (returnValue === '0') {
            sending = false;
            taskIdGlobal = 0;
            sendMsgType = '';
            return {ok: false, error: 'start_task_rejected', return_value: returnValue, dispatch_mode: dispatchMode};
        }
        const scheduledTaskId = taskIdGlobal;
        setTimeout(function () {
            if (sending && sendMsgType === 'text' && taskIdGlobal === scheduledTaskId && inserted) {
                clearInserted(logBuf2RespSeen ? 'timeout_after_log_buf2resp_no_ack' : 'timeout_no_buf2resp_ack', 'restore');
                const timedOutTaskId = taskIdGlobal;
                sending = false;
                taskIdGlobal = 0;
                sendMsgType = '';
                emit('finish_timeout_cleanup', {task_id: timedOutTaskId, msg_type: 'text', proto_written: protoWritten, log_buf2resp_seen: logBuf2RespSeen, ack_seen: ackSeen});
            }
        }, 12000);
        return {ok: true, task_id: taskIdGlobal, return_value: returnValue, dispatch_mode: dispatchMode};
    } catch (e) {
        clearInserted('trigger_exception', 'restore');
        sending = false;
        const err = String(e);
        emit('trigger_error', {task_id: taskIdGlobal, msg_type: 'text', error: err});
        taskIdGlobal = 0;
        sendMsgType = '';
        return {ok: false, error: err};
    }
}

function triggerSendImage(taskId, sender, receiver, protoHex, payloadHex, useLifecycleTemplate) {
    if (defaultStartTaskFunc === null && (!contextReady || triggerX0.isNull())) {
        return {ok: false, error: 'start_task_dispatch_not_ready'};
    }
    if (sending) return {ok: false, error: 'already_sending'};
    if (activeImageGeneration === null) return {ok: false, error: 'image_generation_not_ready'};
    if (activeImageGeneration.uploadFinishedAt <= 0) {
        return {ok: false, error: 'image_upload_not_finished', generation_id: activeImageGeneration.id, file_id: activeImageGeneration.fileId};
    }
    const useTemplate = !!useLifecycleTemplate;
    if (useTemplate && !imageSendTemplateReady) return {ok: false, error: 'image_send_lifecycle_template_not_ready'};
    const payloadBytes = hexToByteArray(payloadHex);
    if (payloadBytes.length !== 0x1a0) return {ok: false, error: 'bad_payload_len_' + payloadBytes.length};

    taskIdGlobal = taskId >>> 0;
    activeImageGeneration.taskId = taskIdGlobal;
    imgProtoHexGlobal = protoHex;
    sendMsgType = 'img';
    inserted = false;
    protoWritten = false;
    cleanupDone = false;
    logBuf2RespSeen = false;
    ackSeen = false;
    ackReadErrors = 0;

    let sendRebaseSummary = null;
    let msgRebaseSummary = null;
    if (useTemplate) {
        sendImgMessageAddr.writeByteArray(imageSendObjectTemplateBytes);
        imgMessageAddr.writeByteArray(imageMessageTemplateBytes);
        const sendMappings = [
            makeRebaseMapping(imageSendObjectTemplateBase, sendImgMessageAddr, imageSendObjectTemplateBytes.length, 'image_send_object'),
            makeRebaseMapping(imageMessageTemplateBase, imgMessageAddr, imageMessageTemplateBytes.length, 'image_message_object'),
        ];
        sendRebaseSummary = rebasePointersInClone(sendImgMessageAddr, imageSendObjectTemplateBytes.length, sendMappings, 'imageSendObject');
        msgRebaseSummary = rebasePointersInClone(imgMessageAddr, imageMessageTemplateBytes.length, sendMappings, 'imageMessageObject');
        sendImgMessageAddr.add(0x28).writePointer(imgMessageAddr);
        imgMessageAddr.add(0x18).writePointer(imgCgiAddr);
    }
    imgMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendImgMessageAddr.add(0x20).writeU32(taskIdGlobal);

    triggerX1Payload.writeByteArray(payloadBytes);
    triggerX1Payload.add(0x18).writePointer(imgCgiAddr);
    triggerX1Payload.add(0xb8).writePointer(triggerX1Payload.add(0xc0));
    triggerX1Payload.add(0x190).writePointer(triggerX1Payload.add(0x198));

    sending = true;
    const dispatchMode = defaultStartTaskFunc !== null ? 'default_manager_wrapper' : 'captured_context';
    emit('triggering', {
        task_id: taskIdGlobal,
        msg_type: 'img',
        sender: sender,
        receiver: receiver,
        x0: triggerX0.toString(),
        dispatch_mode: dispatchMode,
        default_start_task: module.base.add(OFFSETS.defaultStartTaskFuncAddr).toString(),
        x1: triggerX1Payload.toString(),
        proto_len: protoHex.length / 2,
        lifecycle_template: useTemplate,
        generation_id: activeImageGeneration.id,
        file_id: activeImageGeneration.fileId,
        image_send_rebase: sendRebaseSummary,
        image_msg_rebase: msgRebaseSummary,
    });
    try {
        const rv = defaultStartTaskFunc !== null
            ? defaultStartTaskFunc(triggerX1Payload)
            : sendFunc(triggerX0, triggerX1Payload);
        const returnValue = rv.toString();
        emit('trigger_returned', {task_id: taskIdGlobal, return_value: returnValue, dispatch_mode: dispatchMode});
        if (returnValue === '0') {
            sending = false;
            retireActiveImageGeneration('start_task_rejected');
            taskIdGlobal = 0;
            return {ok: false, error: 'start_task_rejected', return_value: returnValue, dispatch_mode: dispatchMode};
        }
        const scheduledTaskId = taskIdGlobal;
        setTimeout(function () {
            if (sending && sendMsgType === 'img' && taskIdGlobal === scheduledTaskId && inserted) {
                clearInserted(logBuf2RespSeen ? 'timeout_after_log_buf2resp_no_ack' : 'timeout_no_buf2resp_ack', sendMsgType === 'img' ? 'null' : 'restore');
                sending = false;
                retireActiveImageGeneration('send_timeout');
                emit('finish_timeout_cleanup', {task_id: taskIdGlobal, proto_written: protoWritten, log_buf2resp_seen: logBuf2RespSeen, ack_seen: ackSeen});
                taskIdGlobal = 0;
            }
        }, 12000);
        return {ok: true, task_id: taskIdGlobal, return_value: returnValue, dispatch_mode: dispatchMode};
    } catch (e) {
        clearInserted('trigger_exception', 'restore');
        sending = false;
        const err = String(e);
        emit('trigger_error', {task_id: taskIdGlobal, error: err});
        retireActiveImageGeneration('send_trigger_error');
        taskIdGlobal = 0;
        return {ok: false, error: err};
    }
}

const module = resourceModule();
setupNativeAllocator();
setupRetOneStub();
setupImageObjects();
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
            persistent_allocs: persistentAllocs.map(function (allocation) {
                return {label: allocation.label, ptr: allocation.ptr, size: allocation.size, kind: allocation.kind};
            }),
            context_ready: contextReady,
            upload_context_ready: uploadContextReady,
            upload_lifecycle_template_ready: uploadTemplateReady,
            upload_lifecycle_template_summary: uploadTemplateSummary,
            upload_callback_lifecycle_template_ready: uploadCallbackTemplateReady,
            upload_callback_override_enabled: uploadCallbackOverrideEnabled,
            force_static_callback_profile: forceStaticCallbackProfile,
            upload_callback_lifecycle_template_summary: uploadCallbackTemplateSummary,
            image_send_lifecycle_template_ready: imageSendTemplateReady,
            image_send_lifecycle_template_summary: imageSendTemplateSummary,
            callback_methods_ready: callbacksReady(),
            learned_get_callback_func: learnedGetCallbackFunc.toString(),
            learned_on_complete_func: learnedOnCompleteFunc.toString(),
            hooks_detached: hooksDetached,
            auto_detach_hooks_after_ack: autoDetachHooksAfterAck,
            auto_detach_upload_hooks_after_finish: autoDetachUploadHooksAfterFinish,
            trigger_x0: triggerX0.toString(),
            upload_x0: uploadGlobalX0.toString(),
            upload_entry_wrapper: hookDetails.uploadImageEntryWrapperAddr,
            image_generation_pool_size: imageGenerations.length,
            image_generation_retention_ms: imageGenerationRetentionMs,
            active_image_generation_id: activeImageGeneration === null ? 0 : activeImageGeneration.id,
        };
    },
    configureCleanup: configureCleanup,
    configure_cleanup: configureCleanup,
    configureGenerationRetention: configureGenerationRetention,
    configure_generation_retention: configureGenerationRetention,
    status: function () {
        return {
            context_ready: contextReady,
            upload_context_ready: uploadContextReady,
            persistent_alloc_count: persistentAllocs.length,
            upload_lifecycle_template_ready: uploadTemplateReady,
            upload_callback_lifecycle_template_ready: uploadCallbackTemplateReady,
            upload_callback_override_enabled: uploadCallbackOverrideEnabled,
            force_static_callback_profile: forceStaticCallbackProfile,
            image_send_lifecycle_template_ready: imageSendTemplateReady,
            callback_methods_ready: callbacksReady(),
            learned_get_callback_func: learnedGetCallbackFunc.toString(),
            learned_on_complete_func: learnedOnCompleteFunc.toString(),
            learned_get_callback_samples: learnedGetCallbackSamples,
            learned_on_complete_samples: learnedOnCompleteSamples,
            sending: sending,
            task_id: taskIdGlobal,
            inserted: inserted,
            proto_written: protoWritten,
            cleanup_done: cleanupDone,
            log_buf2resp_seen: logBuf2RespSeen,
            ack_seen: ackSeen,
            ack_read_errors: ackReadErrors,
            hooks_detached: hooksDetached,
            auto_detach_hooks_after_ack: autoDetachHooksAfterAck,
            auto_detach_upload_hooks_after_finish: autoDetachUploadHooksAfterFinish,
            upload_hook_count: uploadHookListeners.length,
            trigger_x0: triggerX0.toString(),
            upload_x0: uploadGlobalX0.toString(),
            upload_entry_wrapper: hookDetails.uploadImageEntryWrapperAddr,
            image_generation_pool_size: imageGenerations.length,
            image_generation_retention_ms: imageGenerationRetentionMs,
            active_image_generation_id: activeImageGeneration === null ? 0 : activeImageGeneration.id,
            active_image_file_id: activeImageGeneration === null ? '' : activeImageGeneration.fileId,
        };
    },
    triggerUploadImage: function (receiver, md5, imagePath, payloadHex, allowStaticCallbacks, useLifecycleTemplate, forceStaticCallbacks, useEntryWrapper) { return triggerUploadImage(receiver, md5, imagePath, payloadHex, allowStaticCallbacks, useLifecycleTemplate, forceStaticCallbacks, useEntryWrapper); },
    trigger_upload_image: function (receiver, md5, imagePath, payloadHex, allowStaticCallbacks, useLifecycleTemplate, forceStaticCallbacks, useEntryWrapper) { return triggerUploadImage(receiver, md5, imagePath, payloadHex, allowStaticCallbacks, useLifecycleTemplate, forceStaticCallbacks, useEntryWrapper); },
    triggerSendImage: function (taskId, sender, receiver, protoHex, payloadHex, useLifecycleTemplate) { return triggerSendImage(taskId, sender, receiver, protoHex, payloadHex, useLifecycleTemplate); },
    trigger_send_image: function (taskId, sender, receiver, protoHex, payloadHex, useLifecycleTemplate) { return triggerSendImage(taskId, sender, receiver, protoHex, payloadHex, useLifecycleTemplate); },
    triggerSendText: function (taskId, protoHex, payloadHex) { return triggerSendText(taskId, protoHex, payloadHex); },
    trigger_send_text: function (taskId, protoHex, payloadHex) { return triggerSendText(taskId, protoHex, payloadHex); },
    forceCleanup: function () {
        clearInserted('force_cleanup', 'restore');
        sending = false;
        taskIdGlobal = 0;
        retireActiveImageGeneration('force_cleanup');
        detachUploadHooks('force_cleanup');
        detachAllHooks('force_cleanup');
        releasePersistentNativeAllocs('force_cleanup_without_upload');
        return true;
    },
    force_cleanup: function () {
        clearInserted('force_cleanup', 'restore');
        sending = false;
        taskIdGlobal = 0;
        retireActiveImageGeneration('force_cleanup');
        detachUploadHooks('force_cleanup');
        detachAllHooks('force_cleanup');
        releasePersistentNativeAllocs('force_cleanup_without_upload');
        return true;
    },
};
