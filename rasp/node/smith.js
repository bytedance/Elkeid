const path = require('path');
const inspector = require('inspector');
const { SmithClient, OperateEnum } = require('./client');
const { baseProcess, spawnProcess, spawnSyncProcess, connectProcess } = require('./process');

const fs = require('fs');
const net = require('net');
const dns = require('dns');
const child_process = require('child_process');

const smith_client = new SmithClient();

smith_client.on('message', (message) => {
    switch (message.message_type) {
        case OperateEnum.detect:
            if (typeof require.main === 'undefined')
                break;

            const root = path.dirname(require.main.filename);
            const package = path.join(root, 'package.json');

            if (fs.existsSync(package)) {
                const data = fs.readFileSync(package);
                smith_client.postMessage(OperateEnum.detect, {'node': JSON.parse(data)});
            }

            break;

        default:
            break;
    }
});

smith_client.connect();

function smithHook(fn, classID, methodID, process=baseProcess) {
    return function(...args) {
        const smithTrace = {
            'class_id': classID,
            'method_id': methodID,
            'args': args.map(process),
            'stack_trace': new Error().stack.split('\n').slice(1).map(s => s.trim())
        }

        smith_client.postMessage(OperateEnum.trace, smithTrace);

        return fn.call(this, ...args);
    }
}

child_process.ChildProcess.prototype.spawn = smithHook(child_process.ChildProcess.prototype.spawn, 0, 0, spawnProcess);
child_process.spawnSync = smithHook(child_process.spawnSync, 0, 1, spawnSyncProcess);
child_process.execSync = smithHook(child_process.execSync, 0, 2);
child_process.execFileSync = smithHook(child_process.execFileSync, 0, 3);

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

net.Socket.prototype.connect = smithHook(net.Socket.prototype.connect, 2, 0, connectProcess);

dns.lookup = smithHook(dns.lookup, 3, 0);
dns.resolve = smithHook(dns.resolve, 3, 1);
dns.resolve4 = smithHook(dns.resolve4, 3, 2);
dns.resolve6 = smithHook(dns.resolve6, 3, 3);

if (inspector.url()) {
    setTimeout(() => {
        inspector.close();
    }, 500);
}
