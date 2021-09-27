import type { Config } from '@jest/types';
// import { resolve } from 'path';

const config: Config.InitialOptions = {
    verbose: true,
    moduleFileExtensions: ['js', 'json', 'ts'],
    rootDir: '.',
    testMatch: ['**/src/**/*test.[jt]s?(x)','**/test/**/*test.[jt]s?(x)'],
    // testRegex: ["(src|test)/*.(test|spec))\\.[tj]sx?$"],
    testPathIgnorePatterns: [ '<rootDir>/dist/', '<rootDir>/node_modules/'],
    transform: {
        '^.+\\.(t|j)s$': 'ts-jest',
    },
    //   collectCoverageFrom: ['./src/**/*.(t|j)s', '!./node_modules/**'],
    //   coverageDirectory: './coverage/unit',
    testEnvironment: 'node',
    coverageReporters: ['json'],
    coveragePathIgnorePatterns: ['.module.ts$', '.spec.ts$', 'merge-coverage.ts'],
    //   globalSetup: resolve('test/setup.ts'),
    //   globalTeardown: resolve('test/teardown.ts'),
    testTimeout: 60000,
};

export default config;