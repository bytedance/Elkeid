const InspectClient = require('./inspect_client');

if (process.argv.length <= 3) {
    console.log('usage: node injector.js {pid} {expression}');
    process.exit(1);
}

const pid = parseInt(process.argv[2]);
const expression = process.argv[3];

try {
    process._debugProcess(pid);
} catch (e) {
    console.log(e);
    process.exit(1);
}

async function start() {
    try {
        client = new InspectClient();

        await client.connect(9229, '127.0.0.1');
        await client.callMethod('Runtime.enable', {});

        const response = await client.callMethod('Runtime.evaluate', {
            'expression': expression,
            'includeCommandLineAPI': true
        });

        if (response.result.className === 'Error') {
            console.log(response);
            process.exit(2);
        }

        process.exit(0);
    } catch(e) {
        console.log(e);
        process.exit(1);
    }
}

start();