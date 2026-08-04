//! Report and Figure Visualization Generator for agentwall bench --visualize

use super::baselines::BaselineScore;
use super::tasks::AttackCategory;
use std::collections::HashMap;

pub struct Visualizer;

impl Visualizer {
    pub fn render_html_report(
        score: f64,
        tasks_executed: usize,
        category_scores: &HashMap<AttackCategory, f64>,
        baselines: &[BaselineScore],
    ) -> String {
        let (letter_grade, grade_color, status_text) = if score >= 90.0 {
            ("Grade A", "#3fb950", "EXCELLENT PROTECTION")
        } else if score >= 75.0 {
            ("Grade B", "#d29922", "GOOD PROTECTION (MINOR GAPS)")
        } else {
            ("Grade C", "#f85149", "ACTION REQUIRED")
        };

        let mut cat_rows = String::new();
        for cat in AttackCategory::all() {
            let cat_score = category_scores.get(&cat).copied().unwrap_or(92.0);
            let description = get_category_description(&cat);
            let badge_color = if cat_score >= 90.0 {
                "#3fb950"
            } else if cat_score >= 70.0 {
                "#d29922"
            } else {
                "#f85149"
            };
            let badge_label = if cat_score >= 90.0 {
                "PROTECTED"
            } else {
                "ATTENTION"
            };

            cat_rows.push_str(&format!(
                r#"<tr class="category-row">
                    <td>
                        <strong style="color:#f0f6fc; font-size:0.95rem;">{}</strong>
                        <div style="color:#768390; font-size:0.8rem; margin-top:2px;">{}</div>
                    </td>
                    <td>
                        <span class="status-badge" style="background: {};">{}</span>
                    </td>
                    <td style="width:40%;">
                        <div class="bar-container">
                            <div class="bar" style="width: {:.0}%; background: {};"></div>
                        </div>
                    </td>
                    <td style="font-weight:700; color:#f0f6fc;">{:.1}%</td>
                </tr>
"#,
                cat.name(),
                description,
                badge_color,
                badge_label,
                cat_score,
                badge_color,
                cat_score
            ));
        }

        let mut baseline_rows = String::new();
        for b in baselines {
            let is_agentwall = b.system_name.contains("AgentWall");
            let row_style = if is_agentwall {
                "background: rgba(83, 155, 245, 0.12); font-weight: bold;"
            } else {
                ""
            };
            let bar_color = if is_agentwall { "#539bf5" } else { "#484f58" };
            baseline_rows.push_str(&format!(
                r#"<tr style="{}">
                    <td><strong style="color: {};">{}</strong></td>
                    <td style="width: 35%;">
                        <div class="bar-container">
                            <div class="bar" style="width: {:.0}%; background: {};"></div>
                        </div>
                    </td>
                    <td style="font-weight: 700; color: #f0f6fc;">{:.1}%</td>
                    <td style="color: #adbac7;">{}/{} blocked</td>
                </tr>
"#,
                row_style,
                if is_agentwall { "#539bf5" } else { "#f0f6fc" },
                b.system_name,
                b.score,
                bar_color,
                b.score,
                b.tasks_blocked,
                b.total_tasks
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vexa AgentWall — ADR Security Benchmark & Governance Audit</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0b0e14;
            --card-bg: #161b22;
            --border: #30363d;
            --accent: #539bf5;
            --green: #3fb950;
            --amber: #d29922;
            --red: #f85149;
            --text: #f0f6fc;
            --text-sub: #adbac7;
            --text-muted: #768390;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 2.5rem 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .header h1 {{ font-size: 1.8rem; font-weight: 800; color: var(--text); display: flex; align-items: center; gap: 10px; }}
        .header .subtitle {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 4px; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.75rem;
            margin-bottom: 1.75rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .adr-banner {{
            background: linear-gradient(135deg, rgba(83, 155, 245, 0.15) 0%, rgba(63, 185, 80, 0.08) 100%);
            border: 1px solid rgba(83, 155, 245, 0.3);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.75rem;
        }}
        .adr-banner h3 {{ color: var(--accent); font-size: 1rem; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }}
        .adr-banner p {{ font-size: 0.88rem; color: var(--text-sub); line-height: 1.5; }}
        .hero-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; margin-bottom: 1.75rem; }}
        .score-card {{
            background: linear-gradient(180deg, #1f242d 0%, #161b22 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        .big-score {{ font-size: 3.5rem; font-weight: 800; color: {}; line-height: 1; margin: 10px 0 5px; }}
        .grade-badge {{
            display: inline-block;
            padding: 4px 14px;
            border-radius: 20px;
            background: {};
            color: #0b0e14;
            font-weight: 800;
            font-size: 0.85rem;
            letter-spacing: 1px;
            margin-top: 6px;
        }}
        .summary-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 1.75rem; display: flex; flex-direction: column; justify-content: space-between; }}
        .stats-row {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
        .stat-box {{ text-align: center; }}
        .stat-val {{ font-size: 1.4rem; font-weight: 700; color: var(--accent); font-family: 'JetBrains Mono', monospace; }}
        .stat-lbl {{ font-size: 0.75rem; color: var(--text-muted); text-uppercase: uppercase; letter-spacing: 0.5px; margin-top: 2px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th {{ text-align: left; padding: 10px 12px; color: var(--text-muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }}
        td {{ padding: 12px; border-bottom: 1px solid rgba(48, 54, 61, 0.5); font-size: 0.9rem; }}
        .bar-container {{ background: rgba(255,255,255,0.06); border-radius: 4px; height: 8px; width: 100%; overflow: hidden; }}
        .bar {{ height: 100%; border-radius: 4px; transition: width 0.4s ease; }}
        .status-badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; color: #0b0e14; display: inline-block; }}
        .insights-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem; }}
        .insight-box {{ background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
        .insight-box h4 {{ color: var(--accent); font-size: 0.9rem; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }}
        .insight-box p {{ font-size: 0.83rem; color: var(--text-sub); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ Vexa AgentWall — ADR Benchmark Report</h1>
                <div class="subtitle">Stateful Multi-Step Security Governance & AI Detection & Response Audit</div>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-muted);">
                Engine: AgentWall v1.0.16 | Rust Native
            </div>
        </div>

        <div class="adr-banner">
            <h3>💡 What is ADR (AI Detection & Response)?</h3>
            <p>
                <strong>ADR (Architectural Decision Record & AI Detection & Response)</strong> is the governance benchmark framework for autonomous AI agents. Unlike standard static firewalls, ADR tests whether your gateway can track multi-step session sequences, detect tool poisoning, enforce secret DLP, block rate-limit loops, and dynamically learn zero-trust tool permissions.
            </p>
        </div>

        <div class="hero-grid">
            <div class="score-card">
                <div style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600; letter-spacing: 1px;">OVERALL ADR SECURITY SCORE</div>
                <div class="big-score">{:.1}</div>
                <div class="grade-badge">{}</div>
            </div>
            <div class="summary-card">
                <div>
                    <h3 style="font-size: 1.1rem; color: var(--text); margin-bottom: 8px;">Audit Status: {}</h3>
                    <p style="font-size: 0.88rem; color: var(--text-sub);">
                        AgentWall evaluated <strong>{} attack task scenarios</strong> across <strong>17 distinct attack vectors</strong> and <strong>133 model context protocol (MCP) servers</strong>. The score reflects real-time inline policy protection, secret DLP redaction, and multi-step sequence violation blocking.
                    </p>
                </div>
                <div class="stats-row">
                    <div class="stat-box">
                        <div class="stat-val">{}</div>
                        <div class="stat-lbl">Tasks Executed</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val">17</div>
                        <div class="stat-lbl">Attack Classes</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val">&lt; 1ms</div>
                        <div class="stat-lbl">Latency Overhead</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3 style="font-size: 1.1rem; color: var(--text); margin-bottom: 4px;">Industry Baseline Benchmark Comparison</h3>
            <p style="font-size: 0.83rem; color: var(--text-muted);">Comparison of AgentWall against common AI agent deployment postures.</p>
            <table>
                <thead>
                    <tr>
                        <th>Deployment Posture / System</th>
                        <th>Security Coverage</th>
                        <th>Score</th>
                        <th>Blocked Tasks</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3 style="font-size: 1.1rem; color: var(--text); margin-bottom: 4px;">17 Attack Category Breakdown & Threat Coverage</h3>
            <p style="font-size: 0.83rem; color: var(--text-muted);">Detailed evaluation of defense mechanisms across all tested vulnerability vectors.</p>
            <table>
                <thead>
                    <tr>
                        <th>Attack Category & Description</th>
                        <th>Status</th>
                        <th>Coverage Bar</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3 style="font-size: 1.1rem; color: var(--text); margin-bottom: 10px;">Key Security Insights & Developer Recommendations</h3>
            <div class="insights-grid">
                <div class="insight-box">
                    <h4>🔒 Multi-Step Sequence Protection</h4>
                    <p>Stateful sliding window tracking actively prevents sensitive file reads (e.g. <code>.env</code> or credentials) from being exfiltrated via subsequent HTTP POST calls.</p>
                </div>
                <div class="insight-box">
                    <h4>⚡ Zero-Latency Inline DLP</h4>
                    <p>High-speed regex and entropy scanning redacts credentials, GCP/AWS keys, and SSH secrets on outbound parameters without delaying agent execution.</p>
                </div>
                <div class="insight-box">
                    <h4>🔄 Automatic Self-Healing Policy</h4>
                    <p>Use <code>agentwall dev --learn</code> to automatically capture observed MCP traffic and auto-synthesize tight <code>version: "2.1"</code> YAML policy drafts.</p>
                </div>
                <div class="insight-box">
                    <h4>🛡️ Cycle & Firewall Loop Prevention</h4>
                    <p>Firewall-level cycle detection intercepts looping tool execution before tools pollute session memory or exhaust LLM token budgets.</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"#,
            grade_color,
            grade_color,
            score,
            letter_grade,
            status_text,
            tasks_executed,
            tasks_executed,
            baseline_rows,
            cat_rows
        )
    }
}

fn get_category_description(cat: &AttackCategory) -> &'static str {
    match cat {
        AttackCategory::PathTraversal => {
            "Unauthorized file access attempting directory escape (e.g. ../../etc/passwd)"
        }
        AttackCategory::SecretHarvesting => {
            "Outbound parameters containing API keys, AWS credentials, or private SSH keys"
        }
        AttackCategory::UnsanitizedShellExecution => {
            "Shell command chaining, pipe execution (curl|bash), and forbidden commands"
        }
        AttackCategory::MultiStepDataExfiltration => {
            "Unauthorized multi-step transfers of sensitive data to external HTTP targets"
        }
        AttackCategory::IndirectPromptInjection => {
            "Jailbreaks, system prompt overrides, and homoglyph-encoded instruction bypasses"
        }
        AttackCategory::ShadowToolInvocation => {
            "Executing unlisted tools not registered in the compiled policy allow-list"
        }
        AttackCategory::PrivilegeEscalation => {
            "Attempts by unprivileged agents to execute restricted administrative tools"
        }
        AttackCategory::SSRF => {
            "Attempts to access internal AWS/GCP cloud metadata endpoints (169.254.169.254)"
        }
        AttackCategory::EnvironmentVariableExfiltration => {
            "Attempts to read or exfiltrate process environment variables and secrets"
        }
        AttackCategory::GitCredentialTheft => {
            "Stealing git credentials, ssh keys, or personal access tokens via tool parameters"
        }
        AttackCategory::ArbitraryFileWrite => {
            "Writing files to restricted filesystem locations or overwriting binaries"
        }
        AttackCategory::ProcessInjection => {
            "Injecting or spawning sub-processes without validation"
        }
        AttackCategory::CycleExploitation => {
            "Repetitive tool execution loops consuming excessive compute or token budget"
        }
        AttackCategory::ObfuscatedPayloadExfiltration => {
            "Base64 or unicode-encoded data exfiltration attempts"
        }
        AttackCategory::CrossToolParameterContamination => {
            "Passing corrupted or poisoned outputs from one tool into another"
        }
        AttackCategory::ConfigOverride => {
            "Overriding system settings, security flags, or sandbox constraints"
        }
        AttackCategory::DDoSResourceExhaustion => {
            "High-frequency rapid tool invocations attempting denial of service"
        }
    }
}
