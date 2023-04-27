import {nodeResolve} from '@rollup/plugin-node-resolve';
import json from "@rollup/plugin-json";
import commonjs from '@rollup/plugin-commonjs';
import isBuiltin from 'is-builtin-module';

export default {
    input: './src/smith.js',
    output: {
        dir: 'output',
        format: 'cjs'
    },
    plugins: [commonjs(), json(), nodeResolve({resolveOnly: (module) => module === 'string_decoder' || !isBuiltin(module), preferBuiltins: false})]
};
