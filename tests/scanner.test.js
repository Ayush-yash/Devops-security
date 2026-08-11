const { scanSecrets, scanDependencies, scanSAST, scanContainer, scanIaC } = require('../scanner-runner');
const fs = require('fs');
const path = require('path');

describe('Security Scanner Module Tests', () => {
    let mockFiles = {};
    let originalExists, originalReaddir, originalStat, originalReadFile;

    beforeEach(() => {
        mockFiles = {};
        
        originalExists = fs.existsSync;
        originalReaddir = fs.readdirSync;
        originalStat = fs.statSync;
        originalReadFile = fs.readFileSync;

        jest.spyOn(fs, 'existsSync').mockImplementation((filePath) => {
            // Convert to string to avoid potential Buffer path issues
            const pathStr = filePath.toString();
            // If the path is relative and defined in our mock files, intercept
            const normalized = path.relative(process.cwd(), pathStr);
            if (mockFiles[normalized] !== undefined || normalized === '') {
                return true;
            }
            return originalExists(filePath);
        });

        jest.spyOn(fs, 'readdirSync').mockImplementation((dirPath) => {
            const pathStr = dirPath.toString();
            const normalizedDir = path.relative(process.cwd(), pathStr);
            // If it's a mocked directory, list mock files in it
            const files = Object.keys(mockFiles).filter(f => f.startsWith(normalizedDir) && f !== normalizedDir);
            if (files.length > 0) {
                return files.map(f => path.basename(f));
            }
            return originalReaddir(dirPath);
        });

        jest.spyOn(fs, 'statSync').mockImplementation((filePath) => {
            const pathStr = filePath.toString();
            const normalized = path.relative(process.cwd(), pathStr);
            if (mockFiles[normalized] !== undefined) {
                return {
                    isDirectory: () => false,
                    isFile: () => true
                };
            }
            if (normalized === '') {
                return {
                    isDirectory: () => true,
                    isFile: () => false
                };
            }
            return originalStat(filePath);
        });

        jest.spyOn(fs, 'readFileSync').mockImplementation((filePath, options) => {
            const pathStr = filePath.toString();
            const normalized = path.relative(process.cwd(), pathStr);
            if (mockFiles[normalized] !== undefined) {
                return mockFiles[normalized];
            }
            return originalReadFile(filePath, options);
        });
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('scanSecrets detects AWS_KEY and SLACK_TOKEN', () => {
        const slackPart1 = "xoxb-000000000000";
        const slackPart2 = "-000000000000-000000000000000000000000";
        mockFiles['source.js'] = `
            const aws = "AKIA0000000000000000";
            const slack = "` + slackPart1 + slackPart2 + `";
        `;
        const findings = scanSecrets();
        expect(findings.length).toBe(2);
        expect(findings[0].cve).toBe('SEC-SECRET-AWS_KEY');
        expect(findings[1].cve).toBe('SEC-SECRET-SLACK_TOKEN');
    });

    test('scanDependencies identifies vulnerable versions of express and lodash', () => {
        mockFiles['package.json'] = JSON.stringify({
            dependencies: {
                express: "^4.19.1",
                lodash: "4.17.20"
            }
        });
        const findings = scanDependencies();
        expect(findings.length).toBe(2);
        expect(findings.map(f => f.package)).toContain('express');
        expect(findings.map(f => f.package)).toContain('lodash');
    });

    test('scanSAST identifies dangerous eval usage', () => {
        mockFiles['source.js'] = `
            function parse(data) {
                return eval(data);
            }
        `;
        const findings = scanSAST();
        expect(findings.length).toBe(1);
        expect(findings[0].cve).toBe('SAST-DANGEROUS-EVAL');
    });

    test('scanContainer detects obsolete base images', () => {
        mockFiles['Dockerfile'] = `
            FROM node:14
            COPY . .
        `;
        const findings = scanContainer();
        expect(findings.length).toBe(1);
        expect(findings[0].cve).toBe('CVE-2023-38545');
    });

    test('scanIaC detects exposed port 22 in terraform and privileged pod configuration', () => {
        mockFiles['main.tf'] = `
            ingress {
                from_port   = 22
                to_port     = 22
                cidr_blocks = ["0.0.0.0/0"]
            }
        `;
        mockFiles['pod.yaml'] = `
            securityContext:
                privileged: true
        `;
        const findings = scanIaC();
        expect(findings.length).toBe(2);
        expect(findings.map(f => f.cve)).toContain('IAC-OPEN-SSH');
        expect(findings.map(f => f.cve)).toContain('IAC-K8S-PRIVILEGED');
    });
});
