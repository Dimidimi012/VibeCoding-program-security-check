"use strict";
/**
 * Code Sentry VS Code 扩展入口。
 *
 * 功能：
 * - 保存文件时自动扫描（可配置开关）
 * - 手动触发扫描当前文件 / 整个工作区
 * - 结果在 Problems 面板显示 + 侧边栏 TreeView
 * - 状态栏摘要
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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const scanner_1 = require("./scanner");
const diagnostics_1 = require("./diagnostics");
const treeview_1 = require("./treeview");
// ── 全局状态 ───────────────────────────────────────────
let treeProvider;
let autoScanEnabled = true;
// ── 激活入口 ───────────────────────────────────────────
function activate(context) {
    console.log('Code Sentry 已激活');
    // 读取自动扫描配置
    autoScanEnabled = vscode.workspace.getConfiguration('codeSentry').get('autoScan', true);
    // 初始化 TreeView
    treeProvider = new treeview_1.SentryTreeProvider();
    vscode.window.registerTreeDataProvider('code-sentry-findings', treeProvider);
    // 注册命令
    context.subscriptions.push(vscode.commands.registerCommand('code-sentry.scanFile', handleScanFile), vscode.commands.registerCommand('code-sentry.scanWorkspace', handleScanWorkspace), vscode.commands.registerCommand('code-sentry.toggleAutoScan', handleToggleAutoScan), vscode.commands.registerCommand('code-sentry.showReport', handleShowReport), vscode.commands.registerCommand('code-sentry.gotoFinding', handleGotoFinding));
    // 监听文件保存
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (doc) => {
        if (!autoScanEnabled)
            return;
        if (!isScannableFile(doc))
            return;
        await scanAndDisplay(doc.uri.fsPath);
    }));
    // 监听配置变更
    context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('codeSentry.autoScan')) {
            autoScanEnabled = vscode.workspace.getConfiguration('codeSentry').get('autoScan', true);
            vscode.window.showInformationMessage(`Code Sentry 自动扫描: ${autoScanEnabled ? '已开启' : '已关闭'}`);
        }
    }));
    // 启动时扫描当前打开的文件
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor && isScannableFile(activeEditor.document)) {
        scanAndDisplay(activeEditor.document.uri.fsPath);
    }
}
function deactivate() {
    (0, diagnostics_1.clearDiagnostics)();
    (0, diagnostics_1.hideStatusBar)();
}
// ── 命令处理 ────────────────────────────────────────────
async function handleScanFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('没有打开的文件');
        return;
    }
    await scanAndDisplay(editor.document.uri.fsPath);
}
async function handleScanWorkspace() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('没有打开的工作区');
        return;
    }
    const progressOptions = {
        location: vscode.ProgressLocation.Notification,
        title: 'Code Sentry: 扫描工作区...',
        cancellable: false,
    };
    await vscode.window.withProgress(progressOptions, async () => {
        try {
            const result = await (0, scanner_1.scanWorkspace)(folders[0].uri.fsPath);
            (0, diagnostics_1.applyScanResult)(result);
            treeProvider.refresh(result);
            (0, diagnostics_1.updateStatusBar)(result);
            if (result.findings_count === 0) {
                vscode.window.showInformationMessage('✅ Code Sentry: 未发现安全问题');
            }
            else {
                const critical = result.findings.filter(f => f.severity === 'critical').length;
                const high = result.findings.filter(f => f.severity === 'high').length;
                vscode.window.showWarningMessage(`Code Sentry: ${result.findings_count} 个问题 (🔴${critical} 🟠${high})`);
            }
        }
        catch (err) {
            vscode.window.showErrorMessage(`Code Sentry 扫描失败: ${err.message}`);
        }
    });
}
async function handleToggleAutoScan() {
    autoScanEnabled = !autoScanEnabled;
    await vscode.workspace.getConfiguration('codeSentry').update('autoScan', autoScanEnabled, vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage(`Code Sentry 自动扫描: ${autoScanEnabled ? '🟢 已开启' : '⚪ 已关闭'}`);
}
async function handleShowReport() {
    // 聚焦到侧边栏
    await vscode.commands.executeCommand('code-sentry-findings.focus');
}
async function handleGotoFinding(finding) {
    const uri = vscode.Uri.file(finding.file_path);
    const doc = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One });
    const line = Math.max(0, finding.line_number - 1);
    const range = new vscode.Range(line, 0, line, 200);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    editor.selection = new vscode.Selection(range.start, range.start);
}
// ── 核心扫描流程 ────────────────────────────────────────
async function scanAndDisplay(filePath) {
    try {
        const result = await (0, scanner_1.scanFile)(filePath);
        (0, diagnostics_1.applyScanResult)(result);
        treeProvider.refresh(result);
        (0, diagnostics_1.updateStatusBar)(result);
    }
    catch (err) {
        console.error('Code Sentry 扫描错误:', err.message);
        // 静默失败，不打扰用户（避免每次保存都弹窗）
    }
}
function isScannableFile(doc) {
    const scannableLanguages = [
        'python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
        'go', 'java', 'ruby', 'php', 'rust', 'c', 'cpp', 'csharp',
        'shellscript', 'yaml', 'json', 'toml', 'dockerfile', 'markdown',
    ];
    const excludePatterns = vscode.workspace.getConfiguration('codeSentry').get('excludePatterns', []);
    // 检查语言
    if (!scannableLanguages.includes(doc.languageId)) {
        return false;
    }
    // 检查排除模式
    const relativePath = vscode.workspace.asRelativePath(doc.uri);
    for (const pattern of excludePatterns) {
        // 简单的 glob 匹配
        const regex = new RegExp('^' + pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*').replace(/\?/g, '.') + '$');
        if (regex.test(relativePath)) {
            return false;
        }
    }
    return true;
}
//# sourceMappingURL=extension.js.map