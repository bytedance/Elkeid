const Ajv = require('ajv');

const messageSchema = {
    type: 'object',
    properties: {
        message_type: {type: 'integer'},
        data: {type: 'object'}
    },
    required: ['message_type', 'data'],
    additionalProperties: false
};

const matchSchema = {
    type: 'object',
    properties: {
        index: {type: 'integer'},
        regex: {type: 'string'}
    },
    required: ['index', 'regex'],
    additionalProperties: false
};

const filterSchema = {
    type: 'object',
    properties: {
        uuid: {type: 'string'},
        filters: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    class_id: {type: 'integer'},
                    method_id: {type: 'integer'},
                    include: {
                        type: 'array',
                        items: matchSchema
                    },
                    exclude: {
                        type: 'array',
                        items: matchSchema
                    }
                },
                required: ['class_id', 'method_id', 'include', 'exclude']
            }
        }
    },
    required: ['uuid', 'filters'],
    additionalProperties: false
};

const blockSchema = {
    type: 'object',
    properties: {
        uuid: {type: 'string'},
        blocks: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    policy_id: {type: 'string'},
                    class_id: {type: 'integer'},
                    method_id: {type: 'integer'},
                    rules: {
                        type: 'array',
                        items: matchSchema
                    },
                    stack_frame: {
                        type: 'object',
                        nullable: true,
                        properties: {
                            keywords: {
                                type: 'array',
                                items: {
                                    "type": "string"
                                }
                            },
                            operator: {type: 'integer'}
                        }
                    }
                },
                required: ['class_id', 'method_id', 'rules']
            }
        }
    },
    required: ['uuid', 'blocks'],
    additionalProperties: false
};

const ajv = new Ajv();

const validateMessage = ajv.compile(messageSchema);
const validateFilter = ajv.compile(filterSchema);
const validateBlock = ajv.compile(blockSchema);

module.exports = {
    validateMessage,
    validateFilter,
    validateBlock
};