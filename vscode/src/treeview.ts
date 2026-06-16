/**
 * 侧边栏 TreeView：展示扫描摘要和发现详情。
 */

import * as vscode from 'vscode';
import * as path from 'path';
import type { Finding, ScanResult } from './scanner';

// ── Tree Item 类型 ──────────────────────────────────────

type TreeItemType = 'summary' | 'category' | 'finding';

class SentryTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly itemType: TreeItemType,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly finding?: Finding
    ) {
        super(label, collapsibleState);

        if (itemType === 'finding' && finding) {
            this.description = `${path.basename(finding.file_path)}:${finding.line_number}`;
            this.tooltip = [
                `[${finding.rule_id}] ${finding.rule_name}`,
                finding.description,
                finding.context_note || '',
                `建议: ${finding.recommendation}`,
            ].filter(Boolean).join('\n');

            // 点击跳转到对应位置
            this.command = {
                command: 'code-sentry.gotoFinding',
                title: '跳转到发现位置',
                arguments: [finding],
            };
        }
    }

}

// ── Tree Data Provider ──────────────────────────────────

export class SentryTreeProvider implements vscode.TreeDataProvider<SentryTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<SentryTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private lastResult: ScanResult | null = null;

    refresh(result?: ScanResult): void {
        if (result) {
            this.lastResult = result;
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: SentryTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SentryTreeItem): SentryTreeItem[] {
        if (!this.lastResult) {
            return [new SentryTreeItem(
                '尚未执行扫描',
                'summary',
                vscode.TreeItemCollapsibleState.None
            )];
        }

        if (!element) {
            // 根节点
            return this.buildRootItems();
        }

        if (element.itemType === 'category') {
            return this.buildCategoryItems(element.label);
        }

        return [];
    }

    private buildRootItems(): SentryTreeItem[] {
        const r = this.lastResult!;
        const items: SentryTreeItem[] = [];

        // 摘要
        const criticalCount = r.findings.filter(f => f.severity === 'critical').length;
        const highCount = r.findings.filter(f => f.severity === 'high').length;
        const medCount = r.findings.filter(f => f.severity === 'medium').length;

        const summaryParts: string[] = [`📋 ${r.files_scanned} 文件 | ${r.findings_count} 发现`];
        if (criticalCount) summaryParts.push(`🔴${criticalCount}`);
        if (highCount) summaryParts.push(`🟠${highCount}`);
        if (medCount) summaryParts.push(`🟡${medCount}`);
        summaryParts.push(`⏱ ${r.duration_seconds.toFixed(1)}s`);

        items.push(new SentryTreeItem(
            summaryParts.join('  '),
            'summary',
            vscode.TreeItemCollapsibleState.None
        ));

        // 投毒分类
        const poisoningCount = r.findings.filter(f => f.category === 'poisoning').length;
        if (poisoningCount > 0) {
            items.push(new SentryTreeItem(
                `🦠 投毒检测 (${poisoningCount})`,
                'category',
                vscode.TreeItemCollapsibleState.Expanded
            ));
        }

        // 安全分类
        const securityCount = r.findings.filter(f => f.category === 'security').length;
        if (securityCount > 0) {
            items.push(new SentryTreeItem(
                `🔒 安全漏洞 (${securityCount})`,
                'category',
                vscode.TreeItemCollapsibleState.Expanded
            ));
        }

        return items;
    }

    private buildCategoryItems(categoryLabel: string): SentryTreeItem[] {
        const r = this.lastResult!;
        const cat = categoryLabel.startsWith('🦠') ? 'poisoning' : 'security';
        const catFindings = r.findings.filter(f => f.category === cat);

        // 按严重程度排序
        const severityOrder: Record<string, number> = {
            critical: 0, high: 1, medium: 2, low: 3,
        };
        catFindings.sort((a, b) =>
            (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
        );

        const icons: Record<string, string> = {
            critical: '🔴', high: '🟠', medium: '🟡', low: '🔵',
        };

        return catFindings.map(f => {
            const icon = icons[f.severity] || '⚪';
            const label = `${icon} [${f.rule_id}] ${f.rule_name}`;
            const item = new SentryTreeItem(
                label,
                'finding',
                vscode.TreeItemCollapsibleState.None,
                f
            );
            item.description = `${path.basename(f.file_path)}:${f.line_number}`;
            return item;
        });
    }
}
