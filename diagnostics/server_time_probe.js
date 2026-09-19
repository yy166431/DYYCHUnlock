'use strict';

// Optional Frida observation for the UUID below. No network requests are issued.
// Existing callbacks receive their original arguments; responses are not replaced.
// This instrumentation changes timing and is unsuitable for latency measurements.
const EXPECTED_UUID = '79AE6B44-7FE2-3C31-9765-09ED0C83C298';
const CONFIG_URL = 'https://m1.apifoxmock.com/m1/2877214-1694412-default/xx/api/_conf/v1';
const MAX_PENDING = 512;
const attached = new Set();
const listeners = [];
const pendingBlocks = new Map();
const tasks = new Map();
const clockURLs = new Set();
const hostAliases = new Map();
const methodStates = new Map();
const clockDepth = new Map();
const transportDepth = new Map();
let target = null;
let sequence = 0;
let refreshQueued = false;
let sessionClassesScanned = false;

function emit(event, fields) {
    try { send(Object.assign({ probe: 'dyyy-clock-v1', event: event }, fields || {})); }
    catch (_) { /* Diagnostics must not prevent the original operation. */ }
}
function safely(fn, fallback) { try { return fn(); } catch (_) { return fallback; } }
function isNull(value) { return value === null || value === undefined || (value.isNull && value.isNull()); }
function object(value) { return isNull(value) ? null : value.handle ? value : new ObjC.Object(value); }
function string(value) { return isNull(value) ? null : value.toString(); }
function number(value) { return Number(value); }
function exported(name) {
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
    return Module.findExportByName(null, name);
}
function runtime(name, result, args) {
    const address = exported(name);
    return address ? new NativeFunction(address, result, args) : null;
}

function uuidOf(module) {
    return safely(function () {
        const base = module.base;
        if (base.readU32() !== 0xfeedfacf) return null;
        const count = base.add(16).readU32();
        const size = base.add(20).readU32();
        if (count > 4096 || size > 1024 * 1024 || size + 32 > module.size) return null;
        let cursor = base.add(32);
        const end = cursor.add(size);
        for (let i = 0; i < count && cursor.add(8).compare(end) <= 0; ++i) {
            const command = cursor.readU32();
            const length = cursor.add(4).readU32();
            if (length < 8 || cursor.add(length).compare(end) > 0) return null;
            if (command === 0x1b && length >= 24) {
                const bytes = new Uint8Array(cursor.add(8).readByteArray(16));
                const hex = Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('').toUpperCase();
                return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
            }
            cursor = cursor.add(length);
        }
        return null;
    }, null);
}
function owner(address) {
    const module = Process.findModuleByAddress(address);
    return module ? { module: module.name, offset: address.sub(module.base).toString() } : { module: 'unmapped-trampoline' };
}
function endpoint(url) {
    if (!url) return { valid: false, kind: 'nil-url' };
    return safely(function () {
        const parts = ObjC.classes.NSURLComponents.componentsWithURL_resolvingAgainstBaseURL_(url, false);
        const scheme = (string(parts.scheme()) || '').toLowerCase();
        const host = (string(parts.host()) || '').toLowerCase();
        const path = string(parts.percentEncodedPath());
        const query = !isNull(parts.query());
        const fragment = !isNull(parts.fragment());
        const credentials = !isNull(parts.user()) || !isNull(parts.password());
        const valid = (scheme === 'http' || scheme === 'https') && host.length > 0 && !query && !fragment && !credentials;
        if (host && !hostAliases.has(host)) hostAliases.set(host, 'server-' + (hostAliases.size + 1));
        parts.setScheme_(scheme);
        parts.setHost_(host);
        const key = string(parts.string());
        const kind = key === CONFIG_URL ? 'config' : path === '/wx/get_time' ? 'clock' : scheme === 'dyyy-privacy-denied' ? 'locally-denied' : 'other';
        return { valid: valid && (kind === 'clock' || kind === 'config'), kind: kind, key: key,
            scheme: scheme === 'http' || scheme === 'https' ? scheme : 'other',
            host: host ? hostAliases.get(host) : null, hasHost: !!host,
            explicitPort: !isNull(parts.port()), query: query, fragment: fragment, credentials: credentials };
    }, { valid: false, kind: 'unreadable-url' });
}
function publicEndpoint(info) {
    const result = Object.assign({}, info);
    delete result.key; // Never emit host names, arbitrary paths, query strings or credentials.
    return result;
}
function requestInfo(request) {
    if (!request) return { route: { valid: false, kind: 'nil-request' }, method: 'none', body: false, stream: false };
    const method = safely(() => string(request.HTTPMethod()), null);
    return { route: safely(() => endpoint(request.URL()), { valid: false, kind: 'unreadable-request' }),
        method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method) ? method : 'other',
        body: safely(() => number(request.HTTPBody().length()) > 0, false),
        stream: safely(() => !isNull(request.HTTPBodyStream()), false) };
}
function publicRequest(info) {
    return { route: publicEndpoint(info.route), method: info.method, body: info.body, stream: info.stream };
}
function stateOf(task) { return safely(() => number(task.state()), null); }
function attachOnce(key, address, callbacks) {
    const identity = key + ':' + address;
    if (attached.has(identity)) return;
    listeners.push(Interceptor.attach(address, callbacks));
    attached.add(identity);
}
function wrapBlock(address, signature, key, observe) {
    if (isNull(address) || pendingBlocks.has(address.toString())) return;
    if (pendingBlocks.size >= MAX_PENDING) { emit('probe-capacity', { kind: key }); return; }
    const block = new ObjC.Block(address);
    if (!block.types) block.declare(signature);
    const original = block.implementation;
    const pointer = address.toString();
    pendingBlocks.set(pointer, { block: block, original: original });
    block.implementation = function () {
        const args = Array.from(arguments);
        // The sample evaluates its clock/RTT inside the original completion.
        // Do not add logging or JSON parsing before that evaluation.
        try { return original.apply(this, args); }
        finally {
            try { safely(() => observe(args), null); }
            finally { pendingBlocks.delete(pointer); }
        }
    };
}
function completionSummary(dataPtr, responsePtr, errorPtr) {
    const data = object(dataPtr), response = object(responsePtr), error = object(errorPtr);
    const result = { errorCode: error ? safely(() => number(error.code()), null) : null,
        httpStatus: response ? safely(() => number(response.statusCode()), null) : null,
        hasTimestamp: false, jsonObject: false, inspectedJSON: false };
    if (!data) return result;
    const length = safely(() => number(data.length()), 0);
    result.bytes = length;
    if (!length || length > 128 * 1024) return result;
    const json = ObjC.classes.NSJSONSerialization.JSONObjectWithData_options_error_(data, 0, ptr(0));
    result.inspectedJSON = true;
    if (!isNull(json) && json.isKindOfClass_(ObjC.classes.NSDictionary)) {
        result.jsonObject = true;
        result.hasTimestamp = !isNull(json.objectForKey_('timestamp'));
    }
    return result;
}

if (typeof ObjC === 'undefined' || !ObjC.available) {
    emit('unavailable', { reason: 'Objective-C bridge missing; use frida-tools with its Objective-C bridge' });
} else {
    const classImage = runtime('class_getImageName', 'pointer', ['pointer']);
    const superclass = runtime('class_getSuperclass', 'pointer', ['pointer']);
    const impBlock = runtime('imp_getBlock', 'pointer', ['pointer']);

    function belongsToTarget(cls) {
        if (!target || !cls || !classImage) return false;
        return safely(() => classImage(cls.handle).readUtf8String() === target.path, false);
    }
    function methodStatus(method, label) {
        const imp = method.implementation;
        const result = { method: label, imp: owner(imp), status: 'replaced-or-forwarded-imp' };
        if (target && imp.equals(target.base.add(0x605cac))) result.status = 'original-target-imp';
        const block = impBlock ? safely(() => impBlock(imp), null) : null;
        if (!isNull(block)) {
            result.blockInvoke = safely(() => owner(block.add(Process.pointerSize * 2).readPointer()), null);
            if (result.blockInvoke && /DYYCHUnlock/i.test(result.blockInvoke.module)) result.status = 'DYYCHUnlock-block-observer';
        }
        const encoded = JSON.stringify(result);
        if (methodStates.get(label) !== encoded) { methodStates.set(label, encoded); emit('method-state', result); }
    }
    function installClockEntry(address, entry) {
        attachOnce('clock-entry', address, {
            onEnter(args) {
                this.thread = this.threadId;
                const depth = clockDepth.get(this.thread) || 0;
                clockDepth.set(this.thread, depth + 1);
                this.outer = depth === 0;
                if (!this.outer) return;
                const value = safely(() => object(args[2]), null);
                const isString = value && safely(() => value.isKindOfClass_(ObjC.classes.NSString), false);
                const route = isString ? endpoint(ObjC.classes.NSURL.URLWithString_(value)) : { valid: false, kind: 'not-string' };
                if (route.valid && route.kind === 'clock') clockURLs.add(route.key);
                this.id = ++sequence;
                emit('clock-entry', { id: this.id, entry: entry, address: publicEndpoint(route), hasCompletion: !isNull(args[3]) });
                const id = this.id;
                wrapBlock(args[3], { retType: 'void', argTypes: ['double', 'object'] }, 'clock', function (values) {
                    const seconds = number(values[0]);
                    emit('clock-completion', { id: id, serverSeconds: Number.isFinite(seconds) ? seconds : null,
                        serverSecondsFinite: Number.isFinite(seconds), serverSecondsPositive: seconds > 0,
                        hasTimeString: !isNull(values[1]) });
                });
            },
            onLeave() {
                const depth = (clockDepth.get(this.thread) || 1) - 1;
                if (depth) clockDepth.set(this.thread, depth); else clockDepth.delete(this.thread);
            }
        });
    }
    function installTask(task, record) {
        tasks.set(task.handle.toString(), record);
        record.task = task.handle.toString();
        for (const selector of ['- resume', '- cancel']) {
            const method = task[selector];
            if (!method) continue;
            attachOnce(selector, method.implementation, {
                onEnter(args) {
                    this.record = tasks.get(args[0].toString());
                    if (!this.record) return;
                    this.task = object(args[0]);
                    emit(selector === '- resume' ? 'task-resume' : 'task-cancel', { id: this.record.id, state: stateOf(this.task),
                        original: publicRequest(requestInfo(this.task.originalRequest())), current: publicRequest(requestInfo(this.task.currentRequest())) });
                },
                onLeave() {
                    if (this.record) emit('task-state-after-call', { id: this.record.id, operation: selector.slice(2), state: stateOf(this.task) });
                }
            });
        }
    }
    function installSessionClass(cls) {
        for (const selector of ['- dataTaskWithRequest:completionHandler:', '- dataTaskWithURL:completionHandler:',
                                '- dataTaskWithRequest:', '- dataTaskWithURL:']) {
            const method = cls[selector];
            if (!method) continue;
            attachOnce(selector, method.implementation, {
                onEnter(args) {
                    this.thread = this.threadId;
                    if (transportDepth.get(this.thread)) return;
                    if (ObjC.selectorAsString(args[1]) !== selector.slice(2)) return;
                    const input = object(args[2]);
                    const request = selector.includes('WithURL:') ? ObjC.classes.NSURLRequest.requestWithURL_(input) : input;
                    const info = requestInfo(request);
                    if (!info.route.valid || (info.route.kind !== 'config' && !clockURLs.has(info.route.key))) return;
                    transportDepth.set(this.thread, 1);
                    this.record = { id: ++sequence, kind: info.route.kind };
                    const record = this.record;
                    emit('task-create', { id: record.id, selector: selector, request: publicRequest(info) });
                    if (selector.includes('completionHandler:')) wrapBlock(args[3],
                        { retType: 'void', argTypes: ['object', 'object', 'object'] }, 'transport', function (values) {
                            emit('transport-completion', Object.assign({ id: record.id, kind: record.kind }, completionSummary(values[0], values[1], values[2])));
                            if (record.task) tasks.delete(record.task);
                        });
                },
                onLeave(retval) {
                    if (!this.record) return;
                    transportDepth.delete(this.thread);
                    const task = safely(() => object(retval), null);
                    if (!task) { emit('task-return', { id: this.record.id, nilTask: true }); return; }
                    if (tasks.size < MAX_PENDING) installTask(task, this.record);
                    emit('task-return', { id: this.record.id, state: stateOf(task), original: publicRequest(requestInfo(task.originalRequest())) });
                }
            });
        }
    }
    function refresh() {
        const modules = Process.enumerateModules();
        const gate = ObjC.classes.potpiutoideidcs;
        const path = gate && classImage ? safely(() => classImage(gate.handle).readUtf8String(), null) : null;
        const candidate = modules.find(module => module.path === path);
        target = candidate && uuidOf(candidate) === EXPECTED_UUID ? candidate : null;
        for (const module of modules) {
            if (!/libswiftMetal|DYYCHUnlock/i.test(module.name) && module !== candidate) continue;
            const key = 'module:' + module.path + ':' + module.base;
            if (methodStates.has(key)) continue;
            methodStates.set(key, true);
            emit('module', { name: module.name, base: module.base.toString(), size: module.size, uuid: uuidOf(module), supportedTarget: module === target });
        }
        if (!target) { if (!methodStates.has('target-missing')) { methodStates.set('target-missing', true); emit('target-unavailable', { supportedUUID: EXPECTED_UUID }); } return; }
        const clock = ObjC.classes.WCTools;
        if (!belongsToTarget(clock)) { emit('class-mismatch', { class: 'WCTools' }); return; }
        const method = clock['+ requestServerTime:com:'];
        if (method) { methodStatus(method, 'WCTools +requestServerTime:com:'); installClockEntry(method.implementation, 'current-method-imp'); }
        installClockEntry(target.base.add(0x605cac), 'original-target-body');
        const hostGetter = gate['+ mnzqplxkcvbasd'];
        if (hostGetter) attachOnce('time-host', hostGetter.implementation, {
            onLeave(retval) {
                const value = safely(() => object(retval), null);
                const isString = value && safely(() => value.isKindOfClass_(ObjC.classes.NSString), false);
                const route = isString ? endpoint(ObjC.classes.NSURL.URLWithString_('http://' + value.toString() + '/wx/get_time')) : { valid: false, kind: 'nil-or-non-string-host' };
                emit('time-host-getter', { address: publicEndpoint(route) });
            }
        });
        const controller = ObjC.classes.pytpiutoideidcs;
        const setter = belongsToTarget(controller) && controller['- setL_s_time_interval:'];
        if (setter) attachOnce('time-offset', setter.implementation, {
            onEnter(args) { this.instance = object(args[0]); },
            onLeave() {
                const offset = safely(() => number(this.instance.$ivars._l_s_time_interval), NaN);
                emit('time-offset-written', { seconds: Number.isFinite(offset) ? offset : null, readable: Number.isFinite(offset) });
            }
        });
        const session = ObjC.classes.NSURLSession;
        if (!session || !superclass) return;
        if (!sessionClassesScanned) {
            for (const name of Object.keys(ObjC.classes)) {
                const cls = ObjC.classes[name];
                let current = cls.handle;
                let isSession = false;
                for (let depth = 0; depth < 64 && !current.isNull(); ++depth) {
                    if (current.equals(session.handle)) { isSession = true; break; }
                    current = superclass(current);
                }
                if (isSession) safely(() => installSessionClass(cls), null);
            }
            sessionClassesScanned = true;
        }
        for (const selector of ['+ sharedSession', '+ sessionWithConfiguration:', '+ sessionWithConfiguration:delegate:delegateQueue:']) {
            const factory = session[selector];
            if (factory) attachOnce(selector, factory.implementation, {
                onLeave(retval) { safely(() => installSessionClass(object(retval).$class), null); }
            });
        }
    }
    function queueRefresh() {
        if (refreshQueued) return;
        refreshQueued = true;
        setImmediate(function () { refreshQueued = false; safely(refresh, null); });
    }
    emit('probe-start', { supportedUUID: EXPECTED_UUID, timingPerturbed: true, noNetworkRequestsIssued: true });
    if (typeof Process.attachModuleObserver === 'function') {
        listeners.push(Process.attachModuleObserver({ onAdded: queueRefresh }));
    }
    queueRefresh();
    // Catch an application hook replacing an IMP after this probe attaches.
    const refreshTimer = setInterval(queueRefresh, 2000);
    rpc.exports = {
        snapshot() { queueRefresh(); return { pendingCallbacks: pendingBlocks.size, trackedTasks: tasks.size, timingPerturbed: true }; },
        stoprefresh() { clearInterval(refreshTimer); return true; }
    };
}
