/**
 * 扫描器：调用 Python Code Sentry 引擎，返回结构化结果。
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as os from 'os';

// ── 类型定义 ───────────────────────────────────────────

export interface Finding {
    rule_id: string;
    rule_name: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    category: 'poisoning' | 'security';
    file_path: string;
    line_number: number;
    matched_line: string;
    description: string;
    recommendation: string;
    context_note: string;
}

export interface ScanResult {
    scan_path: string;
    files_scanned: number;
    findings_count: number;
    duration_seconds: number;
    findings: Finding[];
}

// ── 配置读取 ───────────────────────────────────────────

function getConfig() {
    const config = vscode.workspace.getConfiguration('codeSentry');
    return {
        pythonPath: config.get<string>('pythonPath', 'python'),
        codeSentryPath: config.get<string>('codeSentryPath', ''),
        autoScan: config.get<boolean>('autoScan', true),
        severity: config.get<string>('severity', 'low'),
        excludePatterns: config.get<string[]>('excludePatterns', []),
    };
}

// ── 引擎路径解析 ───────────────────────────────────────

function resolveCodeSentryPath(configPath: string): string | null {
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

export async function scanFile(filePath: string): Promise<ScanResult> {
    const config = getConfig();
    const enginePath = resolveCodeSentryPath(config.codeSentryPath);
    const python = config.pythonPath;

    let command: string;
    let args: string[];

    if (enginePath) {
        // 直接运行 cli.py
        command = python;
        args = [enginePath, filePath, '--json'];
    } else {
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

        proc.stdout.on('data', (data: Buffer) => {
            stdout += data.toString();
        });

        proc.stderr.on('data', (data: Buffer) => {
            stderr += data.toString();
        });

        proc.on('error', (err: Error) => {
            reject(new Error(`无法启动 Python 引擎: ${err.message}。请确认 Python 已安装且 code-sentry 路径正确`));
        });

        proc.on('close', (code: number | null) => {
            if (code !== 0 && code !== 1 && code !== 2 && code !== null) {
                // 0/1/2 是正常的退出码（表示发现级别）
                reject(new Error(`扫描失败 (exit ${code}): ${stderr}`));
                return;
            }

            try {
                const result = JSON.parse(stdout) as ScanResult;
                resolve(result);
            } catch {
                // JSON 解析失败，可能没有 rich 库的降级输出
                reject(new Error(`无法解析扫描结果。stdout: ${stdout.slice(0, 200)}`));
            }
        });
    });
}

export async function scanWorkspace(workspacePath: string): Promise<ScanResult> {
    const config = getConfig();
    const enginePath = resolveCodeSentryPath(config.codeSentryPath);
    const python = config.pythonPath;

    let command: string;
    let args: string[];

    if (enginePath) {
        command = python;
        args = [enginePath, workspacePath, '--json', '--severity', config.severity];
    } else {
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

        proc.stdout.on('data', (data: Buffer) => {
            stdout += data.toString();
        });

        proc.stderr.on('data', (data: Buffer) => {
            stderr += data.toString();
        });

        proc.on('error', (err: Error) => {
            reject(new Error(`无法启动 Python 引擎: ${err.message}`));
        });

        proc.on('close', (code: number | null) => {
            if (code !== 0 && code !== 1 && code !== 2 && code !== null) {
                reject(new Error(`扫描失败 (exit ${code}): ${stderr}`));
                return;
            }
            try {
                resolve(JSON.parse(stdout));
            } catch {
                reject(new Error('无法解析扫描结果'));
            }
        });
    });
}
