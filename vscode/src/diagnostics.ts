/**
 * 诊断映射：将 Code Sentry 的 Finding 转换为 VS Code Diagnostic。
 */

import * as vscode from 'vscode';
import type { Finding, ScanResult } from './scanner';

// ── 严重程度映射 ───────────────────────────────────────

const severityMap: Record<string, vscode.DiagnosticSeverity> = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
};

// ── 类别图标 ───────────────────────────────────────────

const categoryPrefix: Record<string, string> = {
    poisoning: '🦠',
    security: '🔒',
};

// ── 诊断集合（全局单例）────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;

export function getDiagnosticCollection(): vscode.DiagnosticCollection {
    if (!diagnosticCollection) {
        diagnosticCollection = vscode.languages.createDiagnosticCollection('code-sentry');
    }
    return diagnosticCollection;
}

// ── 核心转换函数 ───────────────────────────────────────

export function applyScanResult(result: ScanResult): void {
    const collection = getDiagnosticCollection();
    collection.clear();

    // 按文件分组
    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of result.findings) {
        const uri = vscode.Uri.file(finding.file_path);
        const key = uri.toString();

        if (!byFile.has(key)) {
            byFile.set(key, []);
        }

        const diag = findingToDiagnostic(finding);
        byFile.get(key)!.push(diag);
    }

    // 设置诊断
    for (const [key, diagnostics] of byFile) {
        const uri = vscode.Uri.parse(key);
        collection.set(uri, diagnostics);
    }
}

export function clearDiagnostics(): void {
    getDiagnosticCollection().clear();
}

function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
    // 计算范围：整行
    const line = Math.max(0, finding.line_number - 1);
    const range = new vscode.Range(line, 0, line, 200);

    const diag = new vscode.Diagnostic(
        range,
        formatMessage(finding),
        severityMap[finding.severity] || vscode.DiagnosticSeverity.Information
    );

    diag.source = 'Code Sentry';
    diag.code = finding.rule_id;

    // 相关链接（可以跳转到规则文档）
    diag.relatedInformation = [];

    return diag;
}

function formatMessage(finding: Finding): string {
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

let statusBarItem: vscode.StatusBarItem;

export function updateStatusBar(result: ScanResult): void {
    if (!statusBarItem) {
        statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
    }

    const critical = result.findings.filter(f => f.severity === 'critical').length;
    const high = result.findings.filter(f => f.severity === 'high').length;
    const total = result.findings_count;

    if (total === 0) {
        statusBarItem.text = `$(shield) Code Sentry: 通过 ✓`;
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = '未发现安全问题';
    } else {
        const badges: string[] = [];
        if (critical > 0) badges.push(`🔴${critical}`);
        if (high > 0) badges.push(`🟠${high}`);
        statusBarItem.text = `$(warning) Code Sentry: ${total} 问题 ${badges.join(' ')}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(
            critical > 0 ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground'
        );
        statusBarItem.tooltip = `${total} 个安全问题\n点击查看详情`;
    }

    statusBarItem.command = 'code-sentry.showReport';
    statusBarItem.show();
}

export function hideStatusBar(): void {
    statusBarItem?.hide();
}
