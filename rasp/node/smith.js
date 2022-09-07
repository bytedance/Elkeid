const path = require('path');
const inspector = require('inspector');
const {SmithClient, OperateEnum} = require('./client');
const {argvProcessor, argvSyncProcessor, socketAddressProcessor} = require('./processor');

const fs = require('fs');
const net = require('net');
const dns = require('dns');
const child_process = require('child_process');

const smith_blocks = new Map();
const smith_filters = new Map();
const smith_client = new SmithClient();

smith_client.on('message', (message) => {
    switch (message.message_type) {
        case OperateEnum.detect:
            if (!require.main)
                break;

            const root = path.dirname(require.main.filename);
            const manifest = path.join(root, 'package.json');

            if (fs.existsSync(manifest)) {
                const data = fs.readFileSync(manifest);
                smith_client.postMessage(OperateEnum.detect, {'node': JSON.parse(data)});
            }

            break;

        case OperateEnum.filter:
            smith_filters.clear();

            for (let filter of message.data.filters) {
                smith_filters.set(`${filter.class_id} ${filter.method_id}`, filter);
            }

            break;

        case OperateEnum.block:
            smith_blocks.clear();

            for (let block of message.data.blocks) {
                smith_blocks.set(`${block.class_id} ${block.method_id}`, block);
            }

            break;

        default:
            break;
    }
});

smith_client.connect();

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

        const pred = (rule) => {
            if (rule.index >= smithTrace.args.length)
                return false;

            return new RegExp(rule.regex).test(smithTrace.args[rule.index]);
        }

        if (canBlock) {
            const block = smith_blocks.get(`${classID} ${methodID}`);

            if (block && block.rules.some(pred)) {
                smithTrace.blocked = true;
                smith_client.postMessage(OperateEnum.trace, smithTrace);
                throw new Error('API blocked by RASP');
            }
        }

        const filter = smith_filters.get(`${classID} ${methodID}`);

        if (!filter) {
            smith_client.postMessage(OperateEnum.trace, smithTrace);
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

        smith_client.postMessage(OperateEnum.trace, smithTrace);

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
