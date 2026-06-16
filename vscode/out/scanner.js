"use strict";
/**
 * 扫描器：调用 Python Code Sentry 引擎，返回结构化结果。
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanFile = scanFile;
exports.scanWorkspace = scanWorkspace;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const path = __importStar(require("path"));
// ── 配置读取 ───────────────────────────────────────────
function getConfig() {
    const config = vscode.workspace.getConfiguration('codeSentry');
    return {
        pythonPath: config.get('pythonPath', 'python'),
        codeSentryPath: config.get('codeSentryPath', ''),
        autoScan: config.get('autoScan', true),
        severity: config.get('severity', 'low'),
        excludePatterns: config.get('excludePatterns', []),
    };
}
// ── 引擎路径解析 ───────────────────────────────────────
function resolveCodeSentryPath(configPath) {
    // 1. 用户配置的路径
    if (configPath && configPath.trim()) {
        const resolved = path.resolve(configPath);
        const cliPath = path.join(resolved, 'code_sentry', 'cli.py');
        return cliPath;
    }
    // 2. 在工作区中查找
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
        for (const folder of workspaceFolders) {
            const candidate = path.join(folder.uri.fsPath, 'code-sentry', 'code_sentry', 'cli.py');
            // 不检查文件是否存在，直接返回候选
            return candidate;
        }
    }
    // 3. 尝试 pip 安装路径（作为模块运行）
    return null; // 返回 null 表示用模块方式：python -m code_sentry.cli
}
// ── 核心扫描函数 ───────────────────────────────────────
async function scanFile(filePath) {
    const config = getConfig();
    const enginePath = resolveCodeSentryPath(config.codeSentryPath);
    const python = config.pythonPath;
    let command;
    let args;
    if (enginePath) {
        // 直接运行 cli.py
        command = python;
        args = [enginePath, filePath, '--json'];
    }
    else {
        // 模块方式运行
        command = python;
        args = ['-m', 'code_sentry.cli', filePath, '--json'];
    }
    // 设置 PYTHONPATH（如果是直接运行 cli.py）
    const env = { ...process.env };
    if (enginePath) {
        const codeSentryRoot = path.resolve(path.dirname(enginePath), '..');
        env.PYTHONPATH = codeSentryRoot;
    }
    return new Promise((resolve, reject) => {
        const proc = cp.spawn(command, args, {
            env,
            cwd: path.dirname(filePath),
            timeout: 30000,
        });
        let stdout = '';
        let stderr = '';
        proc.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        proc.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        proc.on('error', (err) => {
            reject(new Error(`无法启动 Python 引擎: ${err.message}。请确认 Python 已安装且 code-sentry 路径正确`));
        });
        proc.on('close', (code) => {
            if (code !== 0 && code !== 1 && code !== 2 && code !== null) {
                // 0/1/2 是正常的退出码（表示发现级别）
                reject(new Error(`扫描失败 (exit ${code}): ${stderr}`));
                return;
            }
            try {
                const result = JSON.parse(stdout);
                resolve(result);
            }
            catch {
                // JSON 解析失败，可能没有 rich 库的降级输出
                reject(new Error(`无法解析扫描结果。stdout: ${stdout.slice(0, 200)}`));
            }
        });
    });
}
async function scanWorkspace(workspacePath) {
    const config = getConfig();
    const enginePath = resolveCodeSentryPath(config.codeSentryPath);
    const python = config.pythonPath;
    let command;
    let args;
    if (enginePath) {
        command = python;
        args = [enginePath, workspacePath, '--json', '--severity', config.severity];
    }
    else {
        command = python;
        args = ['-m', 'code_sentry.cli', workspacePath, '--json', '--severity', config.severity];
    }
    const env = { ...process.env };
    if (enginePath) {
        env.PYTHONPATH = path.resolve(path.dirname(enginePath), '..');
    }
    return new Promise((resolve, reject) => {
        const proc = cp.spawn(command, args, {
            env,
            cwd: workspacePath,
            timeout: 120000,
        });
        let stdout = '';
        let stderr = '';
        proc.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        proc.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        proc.on('error', (err) => {
            reject(new Error(`无法启动 Python 引擎: ${err.message}`));
        });
        proc.on('close', (code) => {
            if (code !== 0 && code !== 1 && code !== 2 && code !== null) {
                reject(new Error(`扫描失败 (exit ${code}): ${stderr}`));
                return;
            }
            try {
                resolve(JSON.parse(stdout));
            }
            catch {
                reject(new Error('无法解析扫描结果'));
            }
        });
    });
}
//# sourceMappingURL=scanner.js.map