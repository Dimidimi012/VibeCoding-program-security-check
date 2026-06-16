/**
 * Code Sentry VS Code 扩展入口。
 *
 * 功能：
 * - 保存文件时自动扫描（可配置开关）
 * - 手动触发扫描当前文件 / 整个工作区
 * - 结果在 Problems 面板显示 + 侧边栏 TreeView
 * - 状态栏摘要
 */

import * as vscode from 'vscode';
import { scanFile, scanWorkspace } from './scanner';
import {
    applyScanResult,
    clearDiagnostics,
    updateStatusBar,
    hideStatusBar,
} from './diagnostics';
import { SentryTreeProvider } from './treeview';

// ── 全局状态 ───────────────────────────────────────────

let treeProvider: SentryTreeProvider;
let autoScanEnabled: boolean = true;

// ── 激活入口 ───────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
    console.log('Code Sentry 已激活');

    // 读取自动扫描配置
    autoScanEnabled = vscode.workspace.getConfiguration('codeSentry').get('autoScan', true);

    // 初始化 TreeView
    treeProvider = new SentryTreeProvider();
    vscode.window.registerTreeDataProvider('code-sentry-findings', treeProvider);

    // 注册命令
    context.subscriptions.push(
        vscode.commands.registerCommand('code-sentry.scanFile', handleScanFile),
        vscode.commands.registerCommand('code-sentry.scanWorkspace', handleScanWorkspace),
        vscode.commands.registerCommand('code-sentry.toggleAutoScan', handleToggleAutoScan),
        vscode.commands.registerCommand('code-sentry.showReport', handleShowReport),
        vscode.commands.registerCommand('code-sentry.gotoFinding', handleGotoFinding),
    );

    // 监听文件保存
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            if (!autoScanEnabled) return;
            if (!isScannableFile(doc)) return;
            await scanAndDisplay(doc.uri.fsPath);
        })
    );

    // 监听配置变更
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('codeSentry.autoScan')) {
                autoScanEnabled = vscode.workspace.getConfiguration('codeSentry').get('autoScan', true);
                vscode.window.showInformationMessage(
                    `Code Sentry 自动扫描: ${autoScanEnabled ? '已开启' : '已关闭'}`
                );
            }
        })
    );

    // 启动时扫描当前打开的文件
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor && isScannableFile(activeEditor.document)) {
        scanAndDisplay(activeEditor.document.uri.fsPath);
    }
}

export function deactivate(): void {
    clearDiagnostics();
    hideStatusBar();
}

// ── 命令处理 ────────────────────────────────────────────

async function handleScanFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('没有打开的文件');
        return;
    }
    await scanAndDisplay(editor.document.uri.fsPath);
}

async function handleScanWorkspace(): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('没有打开的工作区');
        return;
    }

    const progressOptions: vscode.ProgressOptions = {
        location: vscode.ProgressLocation.Notification,
        title: 'Code Sentry: 扫描工作区...',
        cancellable: false,
    };

    await vscode.window.withProgress(progressOptions, async () => {
        try {
            const result = await scanWorkspace(folders[0].uri.fsPath);
            applyScanResult(result);
            treeProvider.refresh(result);
            updateStatusBar(result);

            if (result.findings_count === 0) {
                vscode.window.showInformationMessage('✅ Code Sentry: 未发现安全问题');
            } else {
                const critical = result.findings.filter(f => f.severity === 'critical').length;
                const high = result.findings.filter(f => f.severity === 'high').length;
                vscode.window.showWarningMessage(
                    `Code Sentry: ${result.findings_count} 个问题 (🔴${critical} 🟠${high})`
                );
            }
        } catch (err: any) {
            vscode.window.showErrorMessage(`Code Sentry 扫描失败: ${err.message}`);
        }
    });
}

async function handleToggleAutoScan(): Promise<void> {
    autoScanEnabled = !autoScanEnabled;
    await vscode.workspace.getConfiguration('codeSentry').update(
        'autoScan',
        autoScanEnabled,
        vscode.ConfigurationTarget.Global
    );
    vscode.window.showInformationMessage(
        `Code Sentry 自动扫描: ${autoScanEnabled ? '🟢 已开启' : '⚪ 已关闭'}`
    );
}

async function handleShowReport(): Promise<void> {
    // 聚焦到侧边栏
    await vscode.commands.executeCommand('code-sentry-findings.focus');
}

async function handleGotoFinding(finding: { file_path: string; line_number: number }): Promise<void> {
    const uri = vscode.Uri.file(finding.file_path);
    const doc = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One });
    const line = Math.max(0, finding.line_number - 1);
    const range = new vscode.Range(line, 0, line, 200);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    editor.selection = new vscode.Selection(range.start, range.start);
}

// ── 核心扫描流程 ────────────────────────────────────────

async function scanAndDisplay(filePath: string): Promise<void> {
    try {
        const result = await scanFile(filePath);
        applyScanResult(result);
        treeProvider.refresh(result);
        updateStatusBar(result);
    } catch (err: any) {
        console.error('Code Sentry 扫描错误:', err.message);
        // 静默失败，不打扰用户（避免每次保存都弹窗）
    }
}

function isScannableFile(doc: vscode.TextDocument): boolean {
    const scannableLanguages = [
        'python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
        'go', 'java', 'ruby', 'php', 'rust', 'c', 'cpp', 'csharp',
        'shellscript', 'yaml', 'json', 'toml', 'dockerfile', 'markdown',
    ];

    const excludePatterns = vscode.workspace.getConfiguration('codeSentry').get<string[]>('excludePatterns', []);

    // 检查语言
    if (!scannableLanguages.includes(doc.languageId)) {
        return false;
    }

    // 检查排除模式
    const relativePath = vscode.workspace.asRelativePath(doc.uri);
    for (const pattern of excludePatterns) {
        // 简单的 glob 匹配
        const regex = new RegExp(
            '^' + pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*').replace(/\?/g, '.') + '$'
        );
        if (regex.test(relativePath)) {
            return false;
        }
    }

    return true;
}
