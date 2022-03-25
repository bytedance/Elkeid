function argvProcessor(obj) {
    if (typeof obj !== 'object' || !obj.hasOwnProperty('args')) {
        return undefined;
    }

    return obj.args.join(' ');
}

function argvSyncProcessor(obj) {
    if (typeof obj !== 'object' || !(obj instanceof Array)) {
        return undefined;
    }

    return obj.join(' ');
}

function socketAddressProcessor(obj) {
    if (!Array.isArray(obj) || obj.length === 0) {
        return undefined;
    }

    let address = obj[0];

    if (!Object.prototype.hasOwnProperty.call(address, 'host') || !Object.prototype.hasOwnProperty.call(address, 'port')) {
        return undefined;
    }

    return `${address.host}:${address.port}`;
}

module.exports = {
    argvProcessor,
    argvSyncProcessor,
    socketAddressProcessor
};