const fs = require('fs');
const InspectClient = require('./inspect_client');

const DEFAULT_PORT = 9229;

function getInspectorPort(pid) {
    const re = new RegExp(/inspect(?:-brk)?=(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}:)?(\d+)/);
    const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8');

    let match = cmdline.match(re);

    if (match !== null) {
        return parseInt(match[1]);
    }

    const environ = fs.readFileSync(`/proc/${pid}/environ`, 'utf8');
    const options = environ.split('\0').find(element => element.startsWith('NODE_OPTIONS='));

    if (typeof options === 'undefined') {
        return DEFAULT_PORT;
    }

    match = options.match(re);

    if (match !== null) {
        return parseInt(match[1]);
    }

    return DEFAULT_PORT;
}

if (process.argv.length <= 3) {
    console.log('usage: node injector.js {pid} {expression} [port]');
    process.exit(1);
}

const pid = parseInt(process.argv[2]);
const expression = process.argv[3];
const port = process.argv.length > 4 ? parseInt(process.argv[4]) : getInspectorPort(pid);

try {
    process._debugProcess(pid);
} catch (e) {
    console.log(e);
    process.exit(1);
}

(async () => {
    try {
        let client = new InspectClient();

        await client.connect(port, '127.0.0.1');
        await client.callMethod('Runtime.enable', {});

        const response = await client.callMethod('Runtime.evaluate', {
            'expression': expression,
            'includeCommandLineAPI': true
        });

        if (response.result.type === 'object' && response.result.subtype === 'error') {
            console.log(response);
            process.exit(2);
        }

        process.exit(0);
    } catch (e) {
        console.log(e);
        process.exit(1);
    }
})();
