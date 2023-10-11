const path = require('path');
const logger = require('./logger');
const {SmithClient, Operate} = require('./client');
const {argvProcessor, argvSyncProcessor, socketAddressProcessor} = require('./processor');
const {validateFilter, validateBlock} = require('./schema');

const fs = require('fs');
const net = require('net');
const dns = require('dns');
const child_process = require('child_process');

const LOGICAL_OR = 0;
const LOGICAL_AND = 1;

const heartbeat = {};

const blocks = new Map();
const filters = new Map();

const client = new SmithClient();

client.on('message', (message) => {
    logger.info(message);

    switch (message.message_type) {
        case Operate.detect:
            if (!require.main)
                break;

            const root = path.dirname(require.main.filename);
            const manifest = path.join(root, 'package.json');

            if (!fs.existsSync(manifest))
                break;

            client.postMessage(Operate.detect, {'node': JSON.parse(fs.readFileSync(manifest))});

            break;

        case Operate.filter:
            if (!validateFilter(message.data)) {
                logger.warn(validateFilter.errors);
                break;
            }

            filters.clear();

            heartbeat.filter = message.data.uuid;

            for (let filter of message.data.filters) {
                filters.set(`${filter.class_id} ${filter.method_id}`, filter);
            }

            break;

        case Operate.block:
            if (!validateBlock(message.data)) {
                logger.warn(validateBlock.errors);
                break;
            }

            blocks.clear();

            heartbeat.block = message.data.uuid;

            for (let block of message.data.blocks) {
                const key = `${block.class_id} ${block.method_id}`;
                blocks.set(key, [block, ...(blocks.get(key) || [])]);
            }

            break;

        default:
            break;
    }
});

client.connect();

setInterval(() => {
    client.postMessage(Operate.heartbeat, heartbeat);
}, 60 * 1000).unref();

function smithHook(func, classID, methodID, canBlock = false, processors = {}) {
    return function (...args) {
        const stringify = (obj, index) => {
            let result;

            if (index in processors) {
                result = processors[index](obj);

                if (result) {
                    return result;
                }
            }

            switch (typeof obj) {
                case 'object':
                    if (obj === null) {
                        result = 'null';
                        break;
                    }

                    result = `object ${obj.constructor.name}`;
                    break;

                case 'function':
                    result = `function ${obj.name}`;
                    break;

                case 'undefined':
                    result = 'undefined';
                    break;

                default:
                    result = obj.toString();
                    break;
            }

            return result;
        }

        const smithTrace = {
            class_id: classID,
            method_id: methodID,
            blocked: false,
            args: args.map(stringify),
            stack_trace: new Error().stack.split('\n').slice(1).map(s => s.trim())
        }

        const pred = rule => {
            if (rule.index >= smithTrace.args.length)
                return false;

            return new RegExp(rule.regex).test(smithTrace.args[rule.index]);
        }

        if (canBlock) {
            const policies = blocks.get(`${classID} ${methodID}`);

            if (policies && policies.some(policy => {
                if (policy.rules.length > 0 && !policy.rules.some(pred))
                    return false;

                if (!policy.stack_frame) {
                    smithTrace.blocked = true;
                    smithTrace.policy_id = policy.policy_id;
                    return true;
                }

                const framePred = keyword => {
                    return smithTrace.stack_trace.some(frame => {
                        return new RegExp(keyword).test(frame);
                    });
                };

                if (policy.stack_frame.operator === LOGICAL_OR && policy.stack_frame.keywords.some(framePred)) {
                    smithTrace.blocked = true;
                    smithTrace.policy_id = policy.policy_id;
                    return true;
                }

                if (policy.stack_frame.operator === LOGICAL_AND && policy.stack_frame.keywords.every(framePred)) {
                    smithTrace.blocked = true;
                    smithTrace.policy_id = policy.policy_id;
                    return true;
                }

                return false;
            })) {
                client.postMessage(Operate.trace, smithTrace);
                throw new Error('API blocked by RASP');
            }
        }

        const filter = filters.get(`${classID} ${methodID}`);

        if (!filter) {
            client.postMessage(Operate.trace, smithTrace);
            return func.call(this, ...args);
        }

        const include = filter.include;
        const exclude = filter.exclude;

        if (include.length > 0 && !include.some(pred)) {
            return func.call(this, ...args);
        }

        if (exclude.length > 0 && exclude.some(pred)) {
            return func.call(this, ...args);
        }

        client.postMessage(Operate.trace, smithTrace);

        return func.call(this, ...args);
    }
}

child_process.ChildProcess.prototype.spawn = smithHook(child_process.ChildProcess.prototype.spawn, 0, 0, true, {0: argvProcessor});
child_process.spawnSync = smithHook(child_process.spawnSync, 0, 1, true, {1: argvSyncProcessor});
child_process.execSync = smithHook(child_process.execSync, 0, 2, true);
child_process.execFileSync = smithHook(child_process.execFileSync, 0, 3, true);

fs.open = smithHook(fs.open, 1, 0);
fs.openSync = smithHook(fs.openSync, 1, 1);
fs.readFile = smithHook(fs.readFile, 1, 2);
fs.readFileSync = smithHook(fs.readFileSync, 1, 3);
fs.readdir = smithHook(fs.readdir, 1, 4);
fs.readdirSync = smithHook(fs.readdirSync, 1, 5);
fs.unlink = smithHook(fs.unlink, 1, 6);
fs.unlinkSync = smithHook(fs.unlinkSync, 1, 7);
fs.rmdir = smithHook(fs.rmdir, 1, 8);
fs.rmdirSync = smithHook(fs.rmdirSync, 1, 9);
fs.rename = smithHook(fs.rename, 1, 10);
fs.renameSync = smithHook(fs.renameSync, 1, 11);

net.Socket.prototype.connect = smithHook(net.Socket.prototype.connect, 2, 0, false, {0: socketAddressProcessor});

dns.lookup = smithHook(dns.lookup, 3, 0);
dns.resolve = smithHook(dns.resolve, 3, 1);
dns.resolve4 = smithHook(dns.resolve4, 3, 2);
dns.resolve6 = smithHook(dns.resolve6, 3, 3);
