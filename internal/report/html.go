package report

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/IvanShishkin/houndoom/internal/ai"
	"github.com/IvanShishkin/houndoom/pkg/models"
)

// escapeJSString escapes a string for safe use in JavaScript
func escapeJSString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// generateHTML generates an HTML report
func (g *Generator) generateHTML(results *models.ScanResults, aiReport *ai.AIReport, outputFile string) error {
	var sb strings.Builder

	// HTML header with Anthropic-inspired theme
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Houndoom Security Scan Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0C0C0C;
            --bg-secondary: #161616;
            --bg-tertiary: #1C1C1C;
            --bg-elevated: #222222;
            --text-primary: #ECECEC;
            --text-secondary: #A0A0A0;
            --text-muted: #6B6B6B;
            --accent: #D97706;
            --accent-light: #78350F;
            --accent-hover: #F59E0B;
            --border-color: #2A2A2A;
            --border-light: #333333;
            --critical-color: #EF4444;
            --critical-bg: #2A1515;
            --critical-border: #7F1D1D;
            --high-color: #F97316;
            --high-bg: #2A1D15;
            --high-border: #7C2D12;
            --medium-color: #EAB308;
            --medium-bg: #2A2515;
            --medium-border: #713F12;
            --low-color: #22C55E;
            --low-bg: #152A1A;
            --low-border: #14532D;
            --info-color: #3B82F6;
            --info-bg: #15202A;
            --info-border: #1E3A5F;
            --code-bg: #0A0A0A;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -2px rgba(0, 0, 0, 0.4);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 32px 24px;
            min-height: 100vh;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            margin-bottom: 32px;
        }
        .header-content {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .header-logo {
            width: 72px;
            height: 72px;
            flex-shrink: 0;
        }
        .header-logo svg {
            width: 100%;
            height: 100%;
        }
        .header-text {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .header h1 {
            font-size: 36px;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: -0.02em;
            margin: 0;
            line-height: 1.1;
        }
        .header p {
            color: var(--text-secondary);
            font-size: 15px;
            margin: 0;
        }

        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            box-shadow: var(--shadow-sm);
            margin-bottom: 24px;
        }
        .card-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
        }
        .card-header h2 {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }
        .card-body { padding: 24px; }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }
        .stat-box {
            background: var(--bg-tertiary);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }
        .stat-box .label {
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        .stat-box .value {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
        }
        .stat-box.critical .value { color: var(--critical-color); }
        .stat-box.high .value { color: var(--high-color); }

        /* Controls */
        .controls {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
            padding: 16px 24px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            border-radius: 12px 12px 0 0;
        }
        .controls-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .controls-label {
            color: var(--text-secondary);
            font-size: 13px;
            font-weight: 500;
        }
        .filter-buttons {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 6px 12px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-secondary);
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            font-family: inherit;
            transition: all 0.15s ease;
        }
        .filter-btn:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .filter-btn.active {
            background: var(--accent);
            border-color: var(--accent);
            color: white;
        }
        .filter-btn.critical.active { background: var(--critical-color); border-color: var(--critical-color); }
        .filter-btn.high.active { background: var(--high-color); border-color: var(--high-color); }
        .filter-btn.medium.active { background: var(--medium-color); border-color: var(--medium-color); }
        .filter-btn.low.active { background: var(--low-color); border-color: var(--low-color); }
        .filter-btn.info.active { background: var(--info-color); border-color: var(--info-color); }

        .sort-select {
            padding: 6px 12px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-family: inherit;
            transition: border-color 0.15s ease;
        }
        .sort-select:focus {
            outline: none;
            border-color: var(--accent);
        }
        .results-count {
            margin-left: auto;
            color: var(--text-secondary);
            font-size: 13px;
        }
        .results-count span {
            color: var(--accent);
            font-weight: 600;
        }

        .findings-list { padding: 16px 24px 24px; }
        .findings-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 16px;
        }

        .finding {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 12px;
            padding: 20px;
        }
        .finding.critical { border-left: 3px solid var(--critical-color); background: var(--critical-bg); }
        .finding.high { border-left: 3px solid var(--high-color); background: var(--high-bg); }
        .finding.medium { border-left: 3px solid var(--medium-color); background: var(--medium-bg); }
        .finding.low { border-left: 3px solid var(--low-color); background: var(--low-bg); }
        .finding.info { border-left: 3px solid var(--info-color); background: var(--info-bg); }
        .finding.hidden { display: none; }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 12px;
        }
        .finding-title {
            font-size: 15px;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1.4;
        }
        .finding-badges {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-shrink: 0;
        }
        .severity {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .severity.critical { background: var(--critical-color); color: white; }
        .severity.high { background: var(--high-color); color: white; }
        .severity.medium { background: var(--medium-color); color: white; }
        .severity.low { background: var(--low-color); color: white; }
        .severity.info { background: var(--info-color); color: white; }

        /* AI Verified badge */
        .ai-verified-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            white-space: nowrap;
            flex-shrink: 0;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.15s ease;
        }
        .ai-verified-badge:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .ai-verified-badge.malicious {
            background: var(--critical-bg);
            border: 1px solid var(--critical-border);
            color: var(--critical-color);
        }
        .ai-verified-badge.malicious:hover {
            background: var(--critical-border);
        }
        .ai-verified-badge.suspicious {
            background: var(--high-bg);
            border: 1px solid var(--high-border);
            color: var(--high-color);
        }
        .ai-verified-badge.suspicious:hover {
            background: var(--high-border);
        }

        /* AI card highlight animation */
        .infected-file-item.highlight {
            animation: aiCardHighlight 2s ease-in-out;
        }
        @keyframes aiCardHighlight {
            0%, 100% { background: var(--bg-tertiary); }
            25% { background: var(--accent-light); border-color: var(--accent); }
            50% { background: var(--bg-tertiary); }
            75% { background: var(--accent-light); border-color: var(--accent); }
        }

        /* Finding highlight animation */
        @keyframes findingHighlight {
            0%, 100% { background: inherit; }
            25% { background: var(--accent-light); }
            50% { background: inherit; }
            75% { background: var(--accent-light); }
        }
        .finding.highlight {
            animation: findingHighlight 2s ease-in-out;
        }
        .finding.critical.highlight {
            animation: findingHighlightCritical 2s ease-in-out;
        }
        .finding.high.highlight {
            animation: findingHighlightHigh 2s ease-in-out;
        }
        @keyframes findingHighlightCritical {
            0%, 100% { background: var(--critical-bg); }
            25% { background: #3d1a1a; }
            50% { background: var(--critical-bg); }
            75% { background: #3d1a1a; }
        }
        @keyframes findingHighlightHigh {
            0%, 100% { background: var(--high-bg); }
            25% { background: #3d2a1a; }
            50% { background: var(--high-bg); }
            75% { background: #3d2a1a; }
        }

        .finding-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 12px;
            font-size: 13px;
            color: var(--text-secondary);
        }
        .finding-meta-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .finding-meta-item strong {
            color: var(--text-muted);
            font-weight: 500;
        }
        .finding-file {
            color: var(--accent);
            font-weight: 500;
            word-break: break-all;
        }
        .copy-btn {
            background: var(--bg-elevated);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            font-family: inherit;
            transition: all 0.15s ease;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .copy-btn:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .copy-btn.copied {
            background: var(--low-bg);
            border-color: var(--low-color);
            color: var(--low-color);
        }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 0;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-tertiary);
            border-radius: 12px 12px 0 0;
        }
        .tab-btn {
            padding: 14px 24px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.15s ease;
            border-bottom: 2px solid transparent;
            margin-bottom: -1px;
        }
        .tab-btn:hover {
            color: var(--text-primary);
        }
        .tab-btn.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }

        /* Export button */
        .export-btn {
            background: var(--accent);
            border: none;
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            font-family: inherit;
            transition: all 0.15s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .export-btn:hover {
            background: var(--accent-hover);
        }

        /* Infected files list */
        .infected-files-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-color);
        }
        .infected-files-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .infected-files-list {
            padding: 16px 24px;
        }
        .infected-file-item {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
        }
        .infected-file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-color);
            gap: 12px;
        }
        .infected-file-path {
            color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            word-break: break-all;
            flex: 1;
        }
        .infected-file-count {
            background: var(--critical-bg);
            border: 1px solid var(--critical-border);
            color: var(--critical-color);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }
        .infected-file-findings {
            padding: 12px 16px;
        }
        .infected-file-finding {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }
        .infected-file-finding:last-child {
            border-bottom: none;
        }
        .infected-file-finding .severity {
            flex-shrink: 0;
        }
        .infected-file-finding-info {
            flex: 1;
        }
        .infected-file-finding-name {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 4px;
        }
        .infected-file-finding-line {
            font-size: 12px;
            color: var(--text-muted);
        }

        /* AI Analysis styles */
        .ai-stats-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            padding: 14px 24px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }
        .ai-stat {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
        }
        .ai-stat-label {
            color: var(--text-muted);
        }
        .ai-stat-label.malicious { color: var(--critical-color); }
        .ai-stat-label.suspicious { color: var(--high-color); }
        .ai-stat-label.false-positive { color: var(--low-color); }
        .ai-stat-value {
            color: var(--text-primary);
            font-weight: 600;
        }
        .ai-stat-value.malicious { color: var(--critical-color); }
        .ai-stat-value.suspicious { color: var(--high-color); }
        .ai-stat-value.false-positive { color: var(--low-color); }
        .ai-confidence {
            background: var(--bg-elevated);
            border: 1px solid var(--border-color);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            color: var(--text-secondary);
            white-space: nowrap;
        }
        .ai-verdict-details {
            padding: 12px 16px;
        }
        .ai-detail-row {
            display: flex;
            gap: 10px;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }
        .ai-detail-row:last-child {
            border-bottom: none;
        }
        .ai-detail-label {
            color: var(--text-muted);
            min-width: 100px;
            flex-shrink: 0;
        }
        .ai-detail-value {
            color: var(--text-secondary);
            line-height: 1.5;
        }
        .ai-indicators code {
            background: var(--bg-elevated);
            border: 1px solid var(--border-color);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            margin-right: 6px;
        }
        .ai-finding-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--accent);
            text-decoration: none;
            font-size: 12px;
            font-weight: 500;
            transition: all 0.15s ease;
            margin-top: 8px;
        }
        .ai-finding-link:hover {
            border-color: var(--accent);
            background: var(--accent-light);
        }
        .ai-finding-link svg {
            width: 14px;
            height: 14px;
        }

        .finding-description {
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 12px;
        }
        .finding-signature {
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 12px;
        }
        .finding-signature strong {
            color: var(--text-secondary);
        }
        .finding-signature code {
            background: var(--bg-elevated);
            border: 1px solid var(--border-color);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: var(--text-secondary);
        }
        .code-block {
            margin-top: 12px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }
        .code-header {
            background: var(--bg-elevated);
            padding: 8px 14px;
            font-size: 11px;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .code-header .line-info {
            color: var(--accent);
            text-transform: none;
            letter-spacing: normal;
        }
        pre.code-fragment {
            background: var(--code-bg);
            color: #E8E8E8;
            padding: 14px 16px;
            margin: 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            line-height: 1.7;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            tab-size: 4;
        }
        .code-fragment::-webkit-scrollbar {
            height: 6px;
        }
        .code-fragment::-webkit-scrollbar-thumb {
            background: var(--border-light);
            border-radius: 3px;
        }

        .no-threats {
            text-align: center;
            padding: 60px 40px;
        }
        .no-threats-icon {
            width: 64px;
            height: 64px;
            background: var(--low-bg);
            border: 2px solid var(--low-border);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            margin: 0 auto 16px;
            color: var(--low-color);
        }
        .no-threats h2 {
            font-size: 20px;
            font-weight: 600;
            color: var(--low-color);
            margin-bottom: 8px;
        }
        .no-threats p {
            color: var(--text-secondary);
            font-size: 14px;
        }

        .footer {
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-size: 13px;
        }
        .footer p { margin-bottom: 4px; }
        .footer strong {
            color: var(--accent);
            font-weight: 600;
        }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-tertiary); border-radius: 3px; }
        ::-webkit-scrollbar-thumb { background: var(--border-dark); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

        @media (max-width: 768px) {
            body { padding: 16px; }
            .controls { flex-direction: column; align-items: stretch; }
            .controls-group { flex-direction: column; align-items: stretch; }
            .filter-buttons { justify-content: flex-start; }
            .results-count { margin-left: 0; margin-top: 8px; }
            .header-content { gap: 12px; }
            .header h1 { font-size: 28px; }
            .finding-header { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="header-logo">
                    <svg viewBox="0 0 99 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M72.6221 4.85022C71.7251 7.10936 70.8946 8.96982 70.7617 8.96982C70.6288 8.96982 69.4993 8.50471 68.2369 7.93992C62.0909 5.116 56.6426 3.98643 49.5332 3.98643C42.756 3.98643 37.4073 4.94989 32.1583 7.1758C31.0953 7.6077 30.1651 7.97314 30.0322 7.97314C29.9325 7.97314 29.9325 6.91002 30.0654 5.58112L30.2979 3.18909L28.9026 4.31866C26.6104 6.11268 24.3181 8.60437 22.9228 10.7638C22.1919 11.8934 21.2949 13.0894 20.863 13.4549C17.408 16.5778 14.3184 19.7339 12.8234 21.7273C8.83687 26.91 5.9466 33.0562 4.41841 39.6675C3.65432 42.9233 3.52143 44.0861 3.52143 49.5014C3.48821 54.2522 3.62109 56.2788 4.0862 58.4383C6.07948 67.7074 9.73385 74.6841 15.8798 81.1293C22.8231 88.3386 30.7298 92.724 40.6963 94.8834C44.4171 95.6808 54.2506 95.6808 57.9714 94.8834C67.6721 92.7572 75.3795 88.6044 82.0238 81.9266C88.5684 75.3818 92.3889 68.2389 94.5815 58.6376C95.0466 56.5446 95.1795 54.6177 95.1795 49.5014C95.1463 43.6542 95.0798 42.6908 94.2825 39.5346C92.0899 30.8303 88.3691 24.0529 82.356 17.7738L79.1335 14.4515L78.602 11.4947C78.0372 8.50471 77.0073 5.48145 75.8114 3.12265C74.3496 0.331949 74.4161 0.298726 72.6221 4.85022ZM76.8412 9.60105C77.4392 11.6276 77.5721 12.9565 77.5389 16.4449C77.5389 20.7306 77.0073 23.621 75.6785 26.8768L75.2134 28.0064L74.4493 26.8768C74.0174 26.2456 73.3197 25.4814 72.8879 25.1492C72.1902 24.6177 72.2234 24.7506 73.3197 27.0761L74.4825 29.5678L73.5855 31.2954C72.3563 33.621 69.9644 37.3751 68.5691 39.1027C67.2402 40.6974 66.3765 40.6974 65.5459 39.0695C63.6191 35.2821 60.2305 31.9599 56.3104 30.0662C55.3137 29.5678 54.4832 29.0695 54.4832 28.9366C54.5164 28.8369 55.812 27.7738 57.3734 26.5778C58.9349 25.3818 60.9614 23.7871 61.8251 22.9898C63.1872 21.7605 63.752 21.4947 65.4795 21.2622C66.609 21.0961 67.5724 20.8967 67.6721 20.7971C67.7718 20.7306 67.207 20.5313 66.4097 20.3652L64.9812 20.0994L66.5758 18.3054C69.2667 15.2821 71.5922 11.1957 73.6187 6.01301L74.5489 3.55454L75.3463 5.31534C75.7449 6.27879 76.4426 8.2057 76.8412 9.60105ZM28.2382 9.50138C27.8395 13.0894 27.8063 17.6741 28.205 19.3353C28.4708 20.5313 28.4708 20.5645 27.4409 20.6642L26.411 20.7638L27.8063 21.528C28.6369 21.9599 29.4342 22.724 29.7664 23.3552C30.0654 23.92 30.9624 25.2821 31.7597 26.312L33.2214 28.2057L31.2946 29.5346C29.102 31.0296 27.9724 32.3585 26.3446 35.4482C25.7466 36.6442 24.9161 38.0064 24.5506 38.4715C23.7533 39.5014 23.7201 39.4682 22.0922 36.013C20.9627 33.6542 19.6006 29.302 19.6006 28.0728C19.6006 27.6741 20.0989 26.5113 20.7302 25.4814C21.9593 23.4881 21.8929 23.0562 20.5973 24.4183C19.4013 25.6808 19.1687 25.4482 19.4345 23.322C19.9328 19.1027 22.059 13.92 24.6503 10.4981C25.9459 8.80371 28.3379 6.27879 28.4708 6.44491C28.5372 6.51135 28.4375 7.87348 28.2382 9.50138ZM51.161 25.7805C52.8885 26.0462 54.4167 26.3785 54.5828 26.5446C54.7157 26.6775 54.151 27.3751 53.3204 28.0396C52.4899 28.7373 51.8255 29.3685 51.8255 29.5014C51.8255 29.6343 52.6228 30.0329 53.5862 30.3652C57.9714 31.8934 62.2902 35.5811 63.9513 39.1692C64.9479 41.3286 65.4463 41.6609 67.6721 41.6609C68.8681 41.6609 68.9345 41.7605 69.2667 44.4183C69.4661 46.0795 69.5989 46.2456 71.7916 48.0396C73.054 49.0695 74.0838 49.9665 74.0838 50.0662C74.0838 50.1326 73.5191 50.0994 72.8546 49.9665C71.6587 49.7672 71.7251 49.8336 74.4161 51.9266C75.9775 53.0894 77.8711 54.7506 78.6684 55.5479L80.0969 57.0429L78.5355 57.2755C77.6718 57.3751 76.1436 57.4748 75.1137 57.4748C74.0838 57.4748 72.4892 57.5745 71.5258 57.6741L69.7983 57.9067L71.5922 59.3353C72.5557 60.1326 73.9842 61.5612 74.7483 62.5246L76.1436 64.2854L72.8879 64.3851L69.6654 64.4848L71.26 66.1127C72.157 67.0097 72.8214 67.807 72.7218 67.9067C72.6553 67.9731 71.559 67.8403 70.2634 67.5745C69.001 67.3419 66.9412 67.1426 65.712 67.1094C63.2869 67.1094 62.7221 67.4748 61.7919 69.7339C61.4597 70.5313 60.9614 70.8967 59.101 71.5944C57.8718 72.0927 55.9449 73.0562 54.8818 73.7539C52.4899 75.2821 48.4369 79.0363 47.4734 80.6309C46.7094 81.827 46.5432 84.219 47.1412 84.817C47.3406 85.0163 47.5067 85.3486 47.5067 85.5811C47.5067 86.0462 45.1812 85.6808 43.3208 84.8834C42.1912 84.4183 42.0251 84.4183 41.4936 84.9167C41.1614 85.2157 40.5966 86.0462 40.2644 86.7439L39.6332 88.0064L39.1681 87.1094C38.703 86.2123 38.703 86.2456 38.6033 87.9399C38.5369 88.9034 38.4372 89.7007 38.3375 89.7007C38.2379 89.7007 37.3741 89.2024 36.4439 88.6044C34.5171 87.3751 33.0885 85.8469 32.2912 84.1525C31.7265 82.9565 31.2281 82.724 31.2281 83.621C31.1949 84.2522 30.4973 85.3818 30.0986 85.3818C29.9989 85.3818 29.8993 84.4515 29.8993 83.2888C29.8993 81.3286 29.8328 81.1293 28.7365 80.0662C27.8063 79.1692 27.6402 78.7705 27.8063 78.106C28.0721 76.9432 28.5704 76.4117 28.5704 77.3087C28.5704 79.3685 39.8325 80.4648 43.7194 78.7705C45.1812 78.106 54.8486 70.2323 55.6127 69.0363C55.8785 68.6044 56.3104 67.1758 56.6093 65.8469C56.8751 64.4848 57.1409 63.322 57.2406 63.2555C57.307 63.1559 57.7057 63.8868 58.1043 64.8502L58.802 66.611L58.6026 64.6509C58.503 63.5878 58.204 62.0263 57.9714 61.1957C57.5396 59.8004 57.5728 59.6343 58.1708 58.7373C58.5362 58.2389 58.9681 57.807 59.1342 57.807C59.2671 57.807 59.6657 58.9034 59.9979 60.1991L60.6291 62.6243L60.7288 59.4682L60.8285 56.312L62.3234 55.3486C63.154 54.817 63.752 54.3519 63.6855 54.2854C63.5194 54.0861 61.0278 54.8502 59.7654 55.5147C59.101 55.8469 57.9382 56.8768 57.1409 57.807C56.3768 58.704 55.513 59.4682 55.2473 59.4682C54.6161 59.4682 53.1875 60.5313 49.6993 63.5878C48.0382 65.0496 47.0083 65.7472 46.8755 65.4814C46.7426 65.2821 46.0449 66.2123 45.2476 67.7406C44.1181 69.8336 43.5533 70.5645 42.4238 71.1957C39.4671 72.9233 38.9687 72.9565 34.1516 72.126C29.7 71.3951 28.5704 70.8967 28.5704 69.7339C28.5704 69.4017 28.9691 68.8702 29.5006 68.5379C31.4939 67.3087 33.753 65.116 34.5171 63.7539C35.3144 62.3253 35.3144 62.3253 34.6167 62.9233C33.9523 63.5213 33.7198 63.5213 32.1251 63.1559C31.1949 62.9233 28.803 62.6575 26.8429 62.5579C24.8496 62.4582 23.255 62.2256 23.255 62.0927C23.255 61.7605 26.1453 56.4781 27.4409 54.4515C27.8728 53.7207 28.8362 52.7572 29.5671 52.2921C30.7963 51.4615 31.0953 51.4283 33.8194 51.5612C36.4439 51.6941 36.9422 51.7937 38.3375 52.724C39.2013 53.322 40.0983 53.8535 40.2976 53.92C40.4969 53.9864 40.0651 55.0163 39.2013 56.3452C37.6731 58.7705 37.8392 58.7373 40.9953 55.9133C42.0916 54.9499 43.1214 54.1525 43.3208 54.1525C43.4869 54.1525 44.3174 54.4848 45.1147 54.8502C46.0449 55.3153 47.2077 55.5811 48.3704 55.5811C51.7922 55.5811 54.0845 53.0894 54.4167 48.9366C54.5828 46.6775 54.3503 46.8768 57.5728 46.312C59.0677 46.0462 59.101 46.013 59.4664 43.621C59.8983 41.0628 59.4996 39.9665 57.4731 38.0728C55.9117 36.611 55.812 36.5446 54.2506 36.7439C51.7258 37.0761 51.3936 37.508 53.6859 37.5412C55.6791 37.5412 55.7456 37.5745 57.2738 39.2024L58.8352 40.8635L58.6026 42.9565C58.4698 44.0861 58.3036 45.116 58.2372 45.2489C58.1708 45.415 57.3734 45.5147 56.5097 45.5147C54.3503 45.5147 53.4201 45.9466 47.8721 49.6343C42.756 53.0562 42.0583 53.2555 39.9654 52.2921C38.3043 51.4947 37.7396 50.4648 37.9721 48.6376C38.105 47.2422 38.404 46.8104 41.0617 44.1193L44.0184 41.0961L40.8624 43.4549C38.0718 45.5479 37.6067 46.013 37.1083 47.4416C36.7097 48.4715 36.61 49.4349 36.7429 49.9997C36.9422 50.8303 36.909 50.8967 36.3442 50.6642C36.012 50.4981 34.5171 50.3319 33.0553 50.2987C30.4308 50.1991 30.3976 50.1991 30.1318 49.2356C29.8993 48.5047 29.9989 47.9399 30.5305 46.91L31.2281 45.5147L30.4308 43.9532C29.7664 42.6575 29.6003 42.5246 29.6003 43.1891C29.6335 43.6542 29.7332 44.3851 29.8661 44.8502C30.0322 45.415 29.9325 46.1127 29.4674 46.9765C28.9026 48.106 28.8694 48.4715 29.2349 49.601C29.6335 50.9964 29.6335 50.9964 28.1718 51.827C27.7067 52.126 27.4077 51.7937 26.3778 49.9333C25.7134 48.6708 24.75 46.9765 24.2184 46.1459C23.3879 44.7506 23.1221 43.7539 23.2218 42.6243C23.255 42.3917 23.8862 41.4283 24.6835 40.4648C25.4808 39.5014 26.71 37.6077 27.4409 36.2456C28.1385 34.9167 29.401 33.0894 30.2315 32.2256C31.9922 30.3652 36.0453 28.106 40.9288 26.2456C44.7161 24.7838 44.6828 24.7838 51.161 25.7805ZM76.1768 34.3851C78.602 35.2821 85.2463 37.0097 88.0369 37.4416L89.864 37.7074L87.6714 38.7705C86.4422 39.3353 84.914 39.9997 84.2496 40.2323C83.5852 40.4648 83.0536 40.7638 83.0536 40.8967C83.0536 41.0296 85.3127 42.5246 88.0369 44.219L93.0201 47.3087V49.6675C93.0201 53.9532 91.9238 60.4981 90.6281 63.9532C89.1664 67.9399 86.1765 73.621 84.8144 75.1824C84.3161 75.714 84.2164 75.6808 83.4855 74.5512C82.5221 73.1559 82.2895 73.2223 82.7214 74.7838C83.3859 77.0429 83.2197 77.4416 80.2963 80.3319C76.808 83.8203 72.8547 86.6775 68.6355 88.7373C65.3466 90.3652 61.9248 91.6276 61.659 91.3286C61.5593 91.229 61.6258 90.5977 61.7919 89.8668C61.958 89.1359 62.1241 87.3751 62.1241 85.9466C62.1241 82.724 61.3268 80.3319 59.4996 78.0064C58.7355 77.0761 58.1708 76.2456 58.2372 76.1791C58.3036 76.1127 59.6325 76.5113 61.1607 77.0429C62.6889 77.5745 63.9845 77.9731 64.051 77.9399C64.3167 77.6741 60.5627 75.5811 58.5694 74.9167L56.3104 74.1525L58.2704 73.2555C59.3667 72.7904 60.6624 72.2921 61.1939 72.1924C61.958 72.0595 62.3234 71.6276 63.0211 70.2323L63.8849 68.4383H66.5426C68.0708 68.4383 70.4295 68.7373 72.157 69.1359C73.7848 69.5346 75.1802 69.7672 75.2798 69.7007C75.3463 69.601 74.8147 68.704 74.0838 67.6741L72.7882 65.7805H75.4127C77.2067 65.7805 78.0704 65.6476 78.0704 65.3818C78.0704 64.9167 75.7117 61.7273 74.1835 60.0994L73.054 58.9034L74.8147 58.704C75.7781 58.5711 77.9708 58.4715 79.665 58.4715C81.3261 58.4715 82.7214 58.3386 82.7214 58.1725C82.7214 58.0064 81.3593 56.5113 79.7315 54.8834C77.6385 52.7572 76.9077 51.8602 77.2731 51.7605C77.6385 51.6941 76.6087 50.5977 74.1835 48.4715L70.5624 45.2489L70.2302 42.4914L69.8979 39.7007L71.4261 37.3751C72.2899 36.0795 73.1536 34.7173 73.3862 34.2854C73.5855 33.8868 73.8181 33.5545 73.8845 33.5545C73.951 33.5545 74.9808 33.92 76.1768 34.3851ZM24.0523 48.5711C23.7201 49.1027 24.5838 52.8901 25.2483 53.8203L25.9459 54.817L25.2483 55.8469C24.4177 56.9765 24.451 57.0097 23.5872 55.2821L22.9228 53.9864L22.9892 56.2788C23.0557 58.106 22.9892 58.6044 22.5241 58.9034C22.1255 59.1692 21.8597 59.1359 21.461 58.8369C21.0291 58.4715 21.0291 58.3054 21.6271 57.3751C22.4577 56.013 22.4244 55.9798 21.2617 55.4814C20.7302 55.2489 20.2651 55.0163 20.2651 54.9831C20.2651 54.9167 20.9295 53.7871 21.76 52.4582C22.5906 51.1293 23.255 49.7007 23.255 49.302C23.255 48.1393 23.6204 47.3751 23.9526 47.8735C24.0855 48.106 24.152 48.405 24.0523 48.5711ZM22.4244 61.7937C21.76 63.1226 21.7932 63.6542 22.7234 65.2489C23.4543 66.5113 24.5506 67.5412 26.5771 68.8037C27.0422 69.1027 27.5738 69.8004 27.8063 70.3984C28.1718 71.3951 28.1385 71.4947 27.3744 71.7937C26.0788 72.2589 25.4808 72.1592 23.8862 71.1293C22.5573 70.2987 22.2583 69.9001 21.2949 67.3751C20.0989 64.2522 20.0989 64.1858 21.8265 61.8602C22.8231 60.5313 23.0889 60.4981 22.4244 61.7937ZM54.151 63.6874L54.1177 65.6143L53.1543 64.4848L52.1577 63.322L52.8885 62.5579C53.2872 62.126 53.7191 61.7937 53.8852 61.7937C54.0181 61.7937 54.151 62.6575 54.151 63.6874ZM29.401 63.7539L30.7298 63.9864L29.102 64.5512C26.9426 65.2821 25.6469 65.2489 24.3513 64.4515C23.7533 64.0861 23.255 63.7206 23.255 63.621C23.255 63.3884 27.8728 63.4549 29.401 63.7539ZM50.9949 67.3751L50.7956 68.5379L49.6328 67.4084L48.4701 66.2788L49.7325 65.2489L50.9949 64.1858L51.0946 65.2157C51.161 65.7805 51.1278 66.7439 50.9949 67.3751ZM53.6859 67.2755L54.5828 68.4715L53.4533 69.4349C52.1909 70.5313 51.6593 70.6974 51.9583 69.9001C52.058 69.601 52.1577 68.6376 52.1577 67.7406C52.1577 66.8436 52.2906 66.1127 52.4567 66.1127C52.656 66.1127 53.1875 66.6442 53.6859 67.2755ZM47.4734 69.4017C47.3073 70.5977 47.108 71.6276 47.0083 71.6941C46.9087 71.7937 46.4768 71.528 46.0117 71.0961L45.2144 70.3319L45.8456 69.0695C46.3771 68.0396 47.5067 66.9432 47.706 67.209C47.7392 67.2422 47.6396 68.2389 47.4734 69.4017ZM50.9949 71.0961C50.9949 71.3286 50.3637 72.0263 49.5664 72.6907L48.1379 73.8868L48.3704 71.7273C48.4701 70.5645 48.6694 69.4682 48.7359 69.3353C48.9352 68.9698 50.9949 70.5645 50.9949 71.0961ZM47.4734 74.2522C47.4734 74.4183 46.9419 74.9831 46.2775 75.5147L45.0483 76.4117L43.7859 75.1824C42.2577 73.6874 42.1912 72.9565 43.5865 72.0927L44.6496 71.4615L46.0449 72.6907C46.809 73.3552 47.4402 74.0529 47.4734 74.2522ZM27.2416 74.518V75.8469L26.3778 75.0496C24.8828 73.6542 24.8164 73.2223 26.112 73.1891C27.2083 73.1559 27.2416 73.1891 27.2416 74.518ZM37.9389 75.8469C38.9687 76.9765 39.8325 78.0396 39.8657 78.2057C39.8657 78.5047 33.3875 78.2389 32.4906 77.9067C32.1916 77.807 31.7929 77.3751 31.5604 76.9432C31.2281 76.312 31.2614 75.9798 31.6932 75.1492C32.6234 73.3552 33.0221 73.1226 34.6167 73.4549C35.7463 73.7206 36.4439 74.1858 37.9389 75.8469ZM41.1946 75.415C40.962 76.3452 40.663 77.0761 40.5302 77.0761C40.364 77.0761 39.6996 76.4449 39.0352 75.6808L37.8392 74.2522L38.7694 74.0529C39.2677 73.92 40.0651 73.6874 40.5302 73.4881C41.5932 73.0894 41.6929 73.3552 41.1946 75.415ZM30.3976 77.3419C30.0322 77.7074 29.2349 76.3452 29.2349 75.4482C29.2681 74.6509 29.3345 74.6841 29.9325 75.8469C30.2979 76.5778 30.5305 77.2422 30.3976 77.3419ZM43.8523 77.0761C43.8523 77.3419 42.3241 78.0728 41.8258 78.0728C41.4936 78.0728 41.6929 76.312 42.0916 75.6476C42.2577 75.3486 43.8523 76.6775 43.8523 77.0761Z" fill="#D97706"/>
                    </svg>
                </div>
                <div class="header-text">
                    <h1>Houndoom</h1>
                    <p>Security scanner for web applications</p>
                </div>
            </div>
        </div>
`)

	// Summary section
	sb.WriteString(`        <div class="card">
            <div class="card-header">
                <h2>Scan Summary</h2>
            </div>
            <div class="card-body">
                <div class="summary-grid">
`)

	sb.WriteString(fmt.Sprintf(`                    <div class="stat-box">
                        <div class="label">Scan Path</div>
                        <div class="value" style="font-size: 14px; word-break: break-all;">%s</div>
                    </div>
`, html.EscapeString(results.ScanPath)))

	sb.WriteString(fmt.Sprintf(`                    <div class="stat-box">
                        <div class="label">Duration</div>
                        <div class="value">%s</div>
                    </div>
`, FormatDuration(results.Duration)))

	sb.WriteString(fmt.Sprintf(`                    <div class="stat-box">
                        <div class="label">Files Scanned</div>
                        <div class="value">%d</div>
                    </div>
`, results.ScannedFiles))

	cssClass := ""
	if results.ThreatsFound > 0 {
		cssClass = "critical"
	}
	sb.WriteString(fmt.Sprintf(`                    <div class="stat-box %s">
                        <div class="label">Threats Found</div>
                        <div class="value">%d</div>
                    </div>
`, cssClass, results.ThreatsFound))

	sb.WriteString(`                </div>
            </div>
        </div>
`)

	// Findings section
	if results.ThreatsFound > 0 {
		// Determine if AI tab should be shown
		hasAIReport := aiReport != nil && len(aiReport.Results) > 0

		sb.WriteString(`        <div class="card" style="overflow: hidden;">
            <div class="tabs">
                <button class="tab-btn active" data-tab="findings">Findings</button>
                <button class="tab-btn" data-tab="infected-files">Infected Files</button>
`)
		if hasAIReport {
			sb.WriteString(`                <button class="tab-btn" data-tab="ai-analysis">AI Analysis</button>
`)
		}
		sb.WriteString(`            </div>
            <div class="tab-content active" id="tab-findings">
                <div class="controls">
                    <div class="controls-group">
                        <span class="controls-label">Filter:</span>
                        <div class="filter-buttons">
                            <button class="filter-btn active" data-filter="all">All</button>
                            <button class="filter-btn critical" data-filter="critical">Critical</button>
                            <button class="filter-btn high" data-filter="high">High</button>
                            <button class="filter-btn medium" data-filter="medium">Medium</button>
                            <button class="filter-btn low" data-filter="low">Low</button>
                            <button class="filter-btn info" data-filter="info">Info</button>
                        </div>
                    </div>
                    <div class="controls-group">
                        <span class="controls-label">Sort:</span>
                        <select class="sort-select" id="sortSelect">
                            <option value="severity-desc">Severity (Critical first)</option>
                            <option value="severity-asc">Severity (Info first)</option>
                            <option value="confidence-desc">Confidence (High first)</option>
                            <option value="confidence-asc">Confidence (Low first)</option>
                            <option value="file-asc">File (A-Z)</option>
                            <option value="file-desc">File (Z-A)</option>
                        </select>
                    </div>
                    <div class="results-count">
                        Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> findings
                    </div>
                </div>
                <div class="findings-list">
                    <div class="findings-title">Detected Threats</div>
                    <div id="findingsContainer">
`)

		// Sort findings by severity before rendering (critical first)
		severityOrder := map[models.Severity]int{
			models.SeverityCritical: 0,
			models.SeverityHigh:     1,
			models.SeverityMedium:   2,
			models.SeverityLow:      3,
			models.SeverityInfo:     4,
		}

		// Create a copy and sort
		sortedFindings := make([]*models.Finding, len(results.Findings))
		copy(sortedFindings, results.Findings)

		// Sort by severity (critical first)
		for i := 0; i < len(sortedFindings)-1; i++ {
			for j := i + 1; j < len(sortedFindings); j++ {
				if severityOrder[sortedFindings[i].Severity] > severityOrder[sortedFindings[j].Severity] {
					sortedFindings[i], sortedFindings[j] = sortedFindings[j], sortedFindings[i]
				}
			}
		}

		// Build a map of AI results by finding ID for quick lookup
		aiResultsMap := make(map[string]*ai.AnalysisResponse)
		if aiReport != nil {
			for _, result := range aiReport.Results {
				aiResultsMap[result.FindingID] = result
			}
		}

		for i, finding := range sortedFindings {
			findingID := fmt.Sprintf("finding-%d", i)
			aiResult := aiResultsMap[findingID]
			aiVerifiedHTML := ""
			if aiResult != nil && (aiResult.Verdict == ai.VerdictMalicious || aiResult.Verdict == ai.VerdictSuspicious) {
				badgeClass := "malicious"
				badgeText := "AI: Malicious"
				if aiResult.Verdict == ai.VerdictSuspicious {
					badgeClass = "suspicious"
					badgeText = "AI: Suspicious"
				}
				aiVerifiedHTML = fmt.Sprintf(`<a href="#ai-%s" class="ai-verified-badge %s" onclick="switchToAITab(event)">%s</a>`, findingID, badgeClass, badgeText)
			}

			sb.WriteString(fmt.Sprintf(`                    <div class="finding %s" id="%s" data-severity="%s" data-confidence="%d" data-file="%s" data-severity-order="%d">
                        <div class="finding-header">
                            <div class="finding-title">#%d %s</div>
                            <div class="finding-badges">
                                %s
                                <span class="severity %s">%s</span>
                            </div>
                        </div>
                        <div class="finding-meta">
                            <div class="finding-meta-item">
                                <strong>File:</strong>
                                <span class="finding-file">%s</span>
                                <button class="copy-btn" onclick="copyPath(this, '%s')">Copy</button>
                            </div>
                            <div class="finding-meta-item">
                                <strong>Line:</strong> %d
                            </div>
                            <div class="finding-meta-item">
                                <strong>Confidence:</strong> %d%%
                            </div>
                        </div>
                        <div class="finding-description">%s</div>
                        <div class="finding-signature"><strong>Signature:</strong> <code>%s</code></div>
                        <div class="code-block">
                            <div class="code-header">
                                <span>Code Fragment</span>
                                <span class="line-info">Line %d</span>
                            </div>
                            <pre class="code-fragment">%s</pre>
                        </div>
                    </div>
`, finding.Severity,
				findingID,
				finding.Severity,
				finding.Confidence,
				html.EscapeString(finding.File.Path),
				severityOrder[finding.Severity],
				i+1,
				html.EscapeString(finding.SignatureName),
				aiVerifiedHTML,
				finding.Severity,
				strings.ToUpper(string(finding.Severity)),
				html.EscapeString(finding.File.Path),
				escapeJSString(finding.File.Path),
				finding.LineNumber,
				finding.Confidence,
				html.EscapeString(finding.Description),
				html.EscapeString(finding.SignatureID),
				finding.LineNumber,
				html.EscapeString(finding.Fragment)))
		}

		sb.WriteString(`                    </div>
                </div>
            </div>
            <div class="tab-content" id="tab-infected-files">
                <div class="infected-files-header">
                    <span class="infected-files-title">Infected Files List</span>
                    <button class="export-btn" onclick="exportPaths()">Export Paths</button>
                </div>
                <div class="infected-files-list">
`)

		// Group findings by file path
		fileFindings := make(map[string][]*models.Finding)
		for _, finding := range results.Findings {
			fileFindings[finding.File.Path] = append(fileFindings[finding.File.Path], finding)
		}

		// Get sorted file paths
		filePaths := make([]string, 0, len(fileFindings))
		for path := range fileFindings {
			filePaths = append(filePaths, path)
		}
		sort.Strings(filePaths)

		// Render infected files list
		for _, filePath := range filePaths {
			findings := fileFindings[filePath]
			sb.WriteString(fmt.Sprintf(`                    <div class="infected-file-item" data-path="%s">
                        <div class="infected-file-header">
                            <span class="infected-file-path">%s</span>
                            <button class="copy-btn" onclick="copyPath(this, '%s')">Copy</button>
                            <span class="infected-file-count">%d findings</span>
                        </div>
                        <div class="infected-file-findings">
`, html.EscapeString(filePath), html.EscapeString(filePath), escapeJSString(filePath), len(findings)))

			for _, f := range findings {
				sb.WriteString(fmt.Sprintf(`                            <div class="infected-file-finding">
                                <span class="severity %s">%s</span>
                                <div class="infected-file-finding-info">
                                    <div class="infected-file-finding-name">%s</div>
                                    <div class="infected-file-finding-line">Line %d · Confidence %d%%</div>
                                </div>
                            </div>
`, f.Severity, strings.ToUpper(string(f.Severity)), html.EscapeString(f.SignatureName), f.LineNumber, f.Confidence))
			}

			sb.WriteString(`                        </div>
                    </div>
`)
		}

		sb.WriteString(`                </div>
            </div>
`)

		// AI Analysis tab content
		if hasAIReport {
			sb.WriteString(`            <div class="tab-content" id="tab-ai-analysis">
                <div class="infected-files-header">
                    <span class="infected-files-title">AI-Powered Analysis</span>
                </div>
`)

			// AI analysis mode
			modeLabel := ""
			if aiReport.IsSmartMode {
				modeLabel = fmt.Sprintf(`<div class="ai-stat"><span class="ai-stat-label">Mode:</span> <span class="ai-stat-value" style="color: var(--accent);">Smart (%d signatures)</span></div>`, aiReport.UniqueSignatures)
			}

			sb.WriteString(`                <div class="ai-stats-bar">
                    ` + modeLabel + `
                    <div class="ai-stat"><span class="ai-stat-label">Model:</span> <span class="ai-stat-value">`)
				sb.WriteString(html.EscapeString(aiReport.Model))
				sb.WriteString(`</span></div>
                    <div class="ai-stat"><span class="ai-stat-label">Analyzed:</span> <span class="ai-stat-value">`)
				sb.WriteString(fmt.Sprintf("%d", aiReport.AnalyzedCount))
				sb.WriteString(`</span></div>
                    <div class="ai-stat"><span class="ai-stat-label malicious">Malicious:</span> <span class="ai-stat-value malicious">`)
				sb.WriteString(fmt.Sprintf("%d", aiReport.MaliciousCount))
				sb.WriteString(`</span></div>
                    <div class="ai-stat"><span class="ai-stat-label suspicious">Suspicious:</span> <span class="ai-stat-value suspicious">`)
				sb.WriteString(fmt.Sprintf("%d", aiReport.SuspiciousCount))
				sb.WriteString(`</span></div>
                    <div class="ai-stat"><span class="ai-stat-label false-positive">False Positives:</span> <span class="ai-stat-value false-positive">`)
				sb.WriteString(fmt.Sprintf("%d", aiReport.FalsePositiveCount))
				sb.WriteString(`</span></div>
                    <div class="ai-stat"><span class="ai-stat-label">Tokens:</span> <span class="ai-stat-value">`)
				sb.WriteString(fmt.Sprintf("%d", aiReport.TotalTokensUsed))
				sb.WriteString(`</span></div>
                </div>
                <div class="infected-files-list">
`)

				// Render AI analysis results
				for i, result := range aiReport.Results {
				verdictClass := ai.GetVerdictColor(result.Verdict)
				// Extract the index from FindingID (format: "finding-N")
				findingIndex := i
				if _, err := fmt.Sscanf(result.FindingID, "finding-%d", &findingIndex); err != nil {
					findingIndex = i
				}

				sb.WriteString(fmt.Sprintf(`                    <div class="infected-file-item" id="ai-%s">
                        <div class="infected-file-header">
                            <span class="infected-file-path">#%d Finding Analysis</span>
                            <span class="severity %s">%s</span>
                            <span class="ai-confidence">%d%% confidence</span>
                        </div>
                        <div class="ai-verdict-details">
                            <div class="ai-detail-row">
                                <span class="ai-detail-label">Risk Level:</span>
                                <span class="ai-detail-value">%s</span>
                            </div>
                            <div class="ai-detail-row">
                                <span class="ai-detail-label">Explanation:</span>
                                <span class="ai-detail-value">%s</span>
                            </div>
`, result.FindingID, i+1, verdictClass, strings.ToUpper(string(result.Verdict)), result.Confidence, result.RiskLevel, html.EscapeString(result.Explanation)))

				if result.Remediation != "" {
					sb.WriteString(fmt.Sprintf(`                            <div class="ai-detail-row">
                                <span class="ai-detail-label">Remediation:</span>
                                <span class="ai-detail-value">%s</span>
                            </div>
`, html.EscapeString(result.Remediation)))
				}

				if len(result.Indicators) > 0 {
					sb.WriteString(`                            <div class="ai-detail-row">
                                <span class="ai-detail-label">Indicators:</span>
                                <span class="ai-detail-value ai-indicators">`)
					for _, indicator := range result.Indicators {
						sb.WriteString(fmt.Sprintf(`<code>%s</code> `, html.EscapeString(indicator)))
					}
					sb.WriteString(`</span>
                            </div>
`)
				}

				// Add link to original finding
				sb.WriteString(fmt.Sprintf(`                            <a href="#%s" class="ai-finding-link" onclick="switchToFindingsTab(event)">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>
                                View Original Finding #%d
                            </a>
`, result.FindingID, findingIndex+1))

				sb.WriteString(`                        </div>
                    </div>
`)
			}

			sb.WriteString(`                </div>
            </div>
`)
		}

		sb.WriteString(`        </div>
`)
	} else {
		sb.WriteString(`        <div class="card">
            <div class="card-body">
                <div class="no-threats">
                    <div class="no-threats-icon">✓</div>
                    <h2>No Threats Detected</h2>
                    <p>Your scanned files appear to be clean.</p>
                </div>
            </div>
        </div>
`)
	}

	// Footer
	sb.WriteString(fmt.Sprintf(`        <div class="footer">
            <p>Generated by <strong><a href="https://github.com/IvanShishkin/houndoom" target="_blank" style="color: var(--accent); text-decoration: none;">Houndoom</a></strong> v%s on %s</p>
            <p>Completed in %s · %d workers · %.2f MB memory</p>
        </div>
    </div>
`, results.Version,
		results.EndTime.Format("2006-01-02 15:04:05"),
		FormatDuration(results.Duration),
		results.Stats.WorkersUsed,
		float64(results.Stats.MemoryUsed)/(1024*1024)))

	// JavaScript for filtering, sorting, tabs, copy and export
	if results.ThreatsFound > 0 {
		sb.WriteString(`
    <script>
    // Copy path function
    function copyPath(btn, path) {
        navigator.clipboard.writeText(path).then(function() {
            btn.classList.add('copied');
            btn.innerHTML = 'Copied';
            setTimeout(function() {
                btn.classList.remove('copied');
                btn.innerHTML = 'Copy';
            }, 2000);
        }).catch(function(err) {
            console.error('Failed to copy:', err);
        });
    }

    // Export paths function
    function exportPaths() {
        const items = document.querySelectorAll('.infected-file-item');
        const paths = Array.from(items).map(item => item.dataset.path);
        const content = paths.join('\n');

        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'infected_files.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Switch to Findings tab and highlight the target finding
    function switchToFindingsTab(event) {
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));

        const findingsBtn = document.querySelector('.tab-btn[data-tab="findings"]');
        const findingsTab = document.getElementById('tab-findings');

        if (findingsBtn && findingsTab) {
            findingsBtn.classList.add('active');
            findingsTab.classList.add('active');
        }

        // Get target finding ID from the href
        const link = event.currentTarget;
        const targetId = link.getAttribute('href').substring(1);
        const targetFinding = document.getElementById(targetId);

        if (targetFinding) {
            // Remove highlight from any previously highlighted finding
            document.querySelectorAll('.finding.highlight').forEach(f => f.classList.remove('highlight'));

            // Add highlight animation
            setTimeout(function() {
                targetFinding.classList.add('highlight');
                // Remove highlight class after animation completes
                setTimeout(function() {
                    targetFinding.classList.remove('highlight');
                }, 2000);
            }, 100);
        }
    }

    // Switch to AI Analysis tab and highlight the target AI card
    function switchToAITab(event) {
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));

        const aiBtn = document.querySelector('.tab-btn[data-tab="ai-analysis"]');
        const aiTab = document.getElementById('tab-ai-analysis');

        if (aiBtn && aiTab) {
            aiBtn.classList.add('active');
            aiTab.classList.add('active');
        }

        // Get target AI card ID from the href
        const link = event.currentTarget;
        const targetId = link.getAttribute('href').substring(1);
        const targetCard = document.getElementById(targetId);

        if (targetCard) {
            // Remove highlight from any previously highlighted card
            document.querySelectorAll('.infected-file-item.highlight').forEach(c => c.classList.remove('highlight'));

            // Add highlight animation
            setTimeout(function() {
                targetCard.classList.add('highlight');
                targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                // Remove highlight class after animation completes
                setTimeout(function() {
                    targetCard.classList.remove('highlight');
                }, 2000);
            }, 100);
        }
    }

    (function() {
        // Tab switching
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                tabBtns.forEach(b => b.classList.remove('active'));
                tabContents.forEach(c => c.classList.remove('active'));

                this.classList.add('active');
                const tabId = 'tab-' + this.dataset.tab;
                document.getElementById(tabId).classList.add('active');
            });
        });

        const container = document.getElementById('findingsContainer');
        const filterBtns = document.querySelectorAll('.filter-btn');
        const sortSelect = document.getElementById('sortSelect');
        const visibleCount = document.getElementById('visibleCount');
        const totalCount = document.getElementById('totalCount');

        let currentFilter = 'all';
        let findings = Array.from(container.querySelectorAll('.finding'));

        // Initialize counts
        totalCount.textContent = findings.length;
        updateVisibleCount();

        // Filter functionality
        filterBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                filterBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                currentFilter = this.dataset.filter;
                applyFilter();
            });
        });

        function applyFilter() {
            findings.forEach(finding => {
                const severity = finding.dataset.severity;
                if (currentFilter === 'all' || severity === currentFilter) {
                    finding.classList.remove('hidden');
                } else {
                    finding.classList.add('hidden');
                }
            });
            updateVisibleCount();
        }

        function updateVisibleCount() {
            const visible = findings.filter(f => !f.classList.contains('hidden')).length;
            visibleCount.textContent = visible;
        }

        // Sort functionality
        sortSelect.addEventListener('change', function() {
            const [field, direction] = this.value.split('-');
            sortFindings(field, direction);
        });

        function sortFindings(field, direction) {
            const sorted = [...findings].sort((a, b) => {
                let aVal, bVal;

                switch(field) {
                    case 'severity':
                        aVal = parseInt(a.dataset.severityOrder);
                        bVal = parseInt(b.dataset.severityOrder);
                        break;
                    case 'confidence':
                        aVal = parseInt(a.dataset.confidence);
                        bVal = parseInt(b.dataset.confidence);
                        break;
                    case 'file':
                        aVal = a.dataset.file.toLowerCase();
                        bVal = b.dataset.file.toLowerCase();
                        if (direction === 'asc') {
                            return aVal.localeCompare(bVal);
                        } else {
                            return bVal.localeCompare(aVal);
                        }
                }

                if (direction === 'asc') {
                    return aVal - bVal;
                } else {
                    return bVal - aVal;
                }
            });

            // Re-append in sorted order
            sorted.forEach((finding, index) => {
                container.appendChild(finding);
                // Update numbering
                const title = finding.querySelector('.finding-title');
                const text = title.textContent;
                title.textContent = text.replace(/#\d+/, '#' + (index + 1));
            });

            findings = sorted;
        }
    })();
    </script>
`)
	}

	sb.WriteString(`</body>
</html>`)

	// Write to file
	return os.WriteFile(outputFile, []byte(sb.String()), 0644)
}
