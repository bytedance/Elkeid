const net = require('net');
const {EventEmitter} = require('events');

const HEADER_SIZE = 4;
const RECONNECT_TIMER = 60 * 1000;
const BUFFER_MAX_SIZE = 1024 * 1024;

const SOCKET_PATH = '/var/run/smith_agent.sock';

const OperateEnum = {
    exit: 0,
    heartbeat: 1,
    trace: 2,
    config: 3,
    control: 4,
    detect: 5,
    filter: 6,
    block: 7
};

class SmithClient extends EventEmitter {
    constructor() {
        super();

        this._buffer = Buffer.alloc(0);
        this._socket = new net.Socket();
        this._connected = false;

        this._socket.on('data', this.onData.bind(this));
        this._socket.on('error', this.onError.bind(this));
        this._socket.on('close', this.onClose.bind(this));
        this._socket.on('connect', this.onConnect.bind(this));

        this._socket.unref();
    }

    connect() {
        this._socket.connect(SOCKET_PATH);
    }

    reconnect() {
        setTimeout(this.connect.bind(this), RECONNECT_TIMER).unref();
    }

    onConnect() {
        this._connected = true;
    }

    onError(err) {

    }

    onClose() {
        this._connected = false;
        this.reconnect();
    }

    onData(data) {
        this._buffer = Buffer.concat([this._buffer, data]);

        while (true) {
            if (this._buffer.length < HEADER_SIZE)
                break;

            const length = this._buffer.readUInt32BE();

            if (this._buffer.length < length + HEADER_SIZE)
                break;

            const message = this._buffer.slice(HEADER_SIZE, HEADER_SIZE + length).toString();
            this.emit('message', JSON.parse(message));

            this._buffer = this._buffer.slice(HEADER_SIZE + length);
        }
    }

    postMessage(operate, data) {
        if (!this._connected)
            return;

        if ('writableLength' in this._socket && this._socket.writableLength > BUFFER_MAX_SIZE)
            return;

        const message = {
            'pid': process.pid,
            'runtime': 'node.js',
            'runtime_version': process.version,
            'time': Date.now(),
            'message_type': operate,
            'probe_version': '1.0.0',
            'data': data
        };

        const payload = JSON.stringify(message);
        const length = Buffer.byteLength(payload);

        const buffer = Buffer.alloc(4 + length);

        buffer.writeUInt32BE(length, 0);
        buffer.write(payload, 4);

        this._socket.write(buffer);
    }
}

module.exports = {
    SmithClient,
    OperateEnum
};