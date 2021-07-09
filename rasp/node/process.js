function baseProcess(obj) {
    result = 'unknown';

    switch (typeof obj) {
        case 'object':
            if (obj === null) {
                result = 'null';
                break;
            }

            result = 'object';
            break;

        case 'function':
            result = 'function';
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

function spawnProcess(obj, index) {
    if (index === 0 && typeof obj === 'object' && obj.hasOwnProperty('args')) {
        return obj.args.join(' ');
    }

    return baseProcess(obj);
}

function spawnSyncProcess(obj, index) {
    if (index === 1 && typeof obj === 'object' && obj instanceof Array) {
        return obj.join(' ');
    }

    return baseProcess(obj);
}

function connectProcess(obj, index) {
    if (index === 0 && Array.isArray(obj) && obj.length > 0) {
        address = obj[0];

        if (Object.prototype.hasOwnProperty.call(address, 'host') && Object.prototype.hasOwnProperty.call(address, 'port')) {
            return `${address.host}:${address.port}`;
        }
    }

    return baseProcess(obj);
}

module.exports = {
    baseProcess,
    spawnProcess,
    spawnSyncProcess,
    connectProcess
};