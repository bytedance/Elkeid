const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new DailyRotateFile({
            dirname: '/tmp',
            filename: `node-probe.${process.pid}.${Date.now()}.log`,
            maxSize: '5m',
            maxFiles: 5,
        })
    ],
});

module.exports = logger;