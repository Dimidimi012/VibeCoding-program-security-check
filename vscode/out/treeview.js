"use strict";
/**
 * 侧边栏 TreeView：展示扫描摘要和发现详情。
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
exports.SentryTreeProvider = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
class SentryTreeItem extends vscode.TreeItem {
    label;
    itemType;
    collapsibleState;
    finding;
    constructor(label, itemType, collapsibleState, finding) {
        super(label, collapsibleState);
        this.label = label;
        this.itemType = itemType;
        this.collapsibleState = collapsibleState;
        this.finding = finding;
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
class SentryTreeProvider {
    _onDidChangeTreeData = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChangeTreeData.event;
    lastResult = null;
    refresh(result) {
        if (result) {
            this.lastResult = result;
        }
        this._onDidChangeTreeData.fire(undefined);
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (!this.lastResult) {
            return [new SentryTreeItem('尚未执行扫描', 'summary', vscode.TreeItemCollapsibleState.None)];
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
    buildRootItems() {
        const r = this.lastResult;
        const items = [];
        // 摘要
        const criticalCount = r.findings.filter(f => f.severity === 'critical').length;
        const highCount = r.findings.filter(f => f.severity === 'high').length;
        const medCount = r.findings.filter(f => f.severity === 'medium').length;
        const summaryParts = [`📋 ${r.files_scanned} 文件 | ${r.findings_count} 发现`];
        if (criticalCount)
            summaryParts.push(`🔴${criticalCount}`);
        if (highCount)
            summaryParts.push(`🟠${highCount}`);
        if (medCount)
            summaryParts.push(`🟡${medCount}`);
        summaryParts.push(`⏱ ${r.duration_seconds.toFixed(1)}s`);
        items.push(new SentryTreeItem(summaryParts.join('  '), 'summary', vscode.TreeItemCollapsibleState.None));
        // 投毒分类
        const poisoningCount = r.findings.filter(f => f.category === 'poisoning').length;
        if (poisoningCount > 0) {
            items.push(new SentryTreeItem(`🦠 投毒检测 (${poisoningCount})`, 'category', vscode.TreeItemCollapsibleState.Expanded));
        }
        // 安全分类
        const securityCount = r.findings.filter(f => f.category === 'security').length;
        if (securityCount > 0) {
            items.push(new SentryTreeItem(`🔒 安全漏洞 (${securityCount})`, 'category', vscode.TreeItemCollapsibleState.Expanded));
        }
        return items;
    }
    buildCategoryItems(categoryLabel) {
        const r = this.lastResult;
        const cat = categoryLabel.startsWith('🦠') ? 'poisoning' : 'security';
        const catFindings = r.findings.filter(f => f.category === cat);
        // 按严重程度排序
        const severityOrder = {
            critical: 0, high: 1, medium: 2, low: 3,
        };
        catFindings.sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
        const icons = {
            critical: '🔴', high: '🟠', medium: '🟡', low: '🔵',
        };
        return catFindings.map(f => {
            const icon = icons[f.severity] || '⚪';
            const label = `${icon} [${f.rule_id}] ${f.rule_name}`;
            const item = new SentryTreeItem(label, 'finding', vscode.TreeItemCollapsibleState.None, f);
            item.description = `${path.basename(f.file_path)}:${f.line_number}`;
            return item;
        });
    }
}
exports.SentryTreeProvider = SentryTreeProvider;
//# sourceMappingURL=treeview.js.map