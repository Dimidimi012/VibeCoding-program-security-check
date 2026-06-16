"use strict";
/**
 * 诊断映射：将 Code Sentry 的 Finding 转换为 VS Code Diagnostic。
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
exports.getDiagnosticCollection = getDiagnosticCollection;
exports.applyScanResult = applyScanResult;
exports.clearDiagnostics = clearDiagnostics;
exports.updateStatusBar = updateStatusBar;
exports.hideStatusBar = hideStatusBar;
const vscode = __importStar(require("vscode"));
// ── 严重程度映射 ───────────────────────────────────────
const severityMap = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
};
// ── 类别图标 ───────────────────────────────────────────
const categoryPrefix = {
    poisoning: '🦠',
    security: '🔒',
};
// ── 诊断集合（全局单例）────────────────────────────────
let diagnosticCollection;
function getDiagnosticCollection() {
    if (!diagnosticCollection) {
        diagnosticCollection = vscode.languages.createDiagnosticCollection('code-sentry');
    }
    return diagnosticCollection;
}
// ── 核心转换函数 ───────────────────────────────────────
function applyScanResult(result) {
    const collection = getDiagnosticCollection();
    collection.clear();
    // 按文件分组
    const byFile = new Map();
    for (const finding of result.findings) {
        const uri = vscode.Uri.file(finding.file_path);
        const key = uri.toString();
        if (!byFile.has(key)) {
            byFile.set(key, []);
        }
        const diag = findingToDiagnostic(finding);
        byFile.get(key).push(diag);
    }
    // 设置诊断
    for (const [key, diagnostics] of byFile) {
        const uri = vscode.Uri.parse(key);
        collection.set(uri, diagnostics);
    }
}
function clearDiagnostics() {
    getDiagnosticCollection().clear();
}
function findingToDiagnostic(finding) {
    // 计算范围：整行
    const line = Math.max(0, finding.line_number - 1);
    const range = new vscode.Range(line, 0, line, 200);
    const diag = new vscode.Diagnostic(range, formatMessage(finding), severityMap[finding.severity] || vscode.DiagnosticSeverity.Information);
    diag.source = 'Code Sentry';
    diag.code = finding.rule_id;
    // 相关链接（可以跳转到规则文档）
    diag.relatedInformation = [];
    return diag;
}
function formatMessage(finding) {
    const prefix = categoryPrefix[finding.category] || '';
    const parts = [
        `${prefix} [${finding.rule_id}] ${finding.rule_name}`,
        finding.description,
    ];
    if (finding.context_note && finding.context_note !== finding.description) {
        parts.push(`→ ${finding.context_note}`);
    }
    parts.push(`💡 ${finding.recommendation}`);
    return parts.join('\n');
}
// ── 状态栏 ─────────────────────────────────────────────
let statusBarItem;
function updateStatusBar(result) {
    if (!statusBarItem) {
        statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    }
    const critical = result.findings.filter(f => f.severity === 'critical').length;
    const high = result.findings.filter(f => f.severity === 'high').length;
    const total = result.findings_count;
    if (total === 0) {
        statusBarItem.text = `$(shield) Code Sentry: 通过 ✓`;
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = '未发现安全问题';
    }
    else {
        const badges = [];
        if (critical > 0)
            badges.push(`🔴${critical}`);
        if (high > 0)
            badges.push(`🟠${high}`);
        statusBarItem.text = `$(warning) Code Sentry: ${total} 问题 ${badges.join(' ')}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(critical > 0 ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground');
        statusBarItem.tooltip = `${total} 个安全问题\n点击查看详情`;
    }
    statusBarItem.command = 'code-sentry.showReport';
    statusBarItem.show();
}
function hideStatusBar() {
    statusBarItem?.hide();
}
//# sourceMappingURL=diagnostics.js.map