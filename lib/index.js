/**
 * dsh-agent-guard — pre-execute gate for the MECHANICALLY CHECKABLE rules in
 * AGENTS.md.
 *
 * Why this exists: "never print a credential" and "never stop a service or
 * driver" are deterministic — a regex decides them. Enforcing those by asking
 * the model to remember a prompt is the wrong layer; a `tools/pre-execute`
 * listener is the right one. Semantic rules (diagnose-before-fixing, confirm
 * intent) stay in AGENTS.md, because no gate can decide those.
 *
 * Behaviour: every rule returns an ASK decision, never a hard deny. The user
 * sees the exact rule and the offending text and decides. With no answerer
 * available the call fails closed, which is the safe direction.
 *
 * Tuning: edit the two rule tables below. They are plain regexes on purpose —
 * this file is the config.
 */

export const name = 'agent-guard'

import { fileURLToPath } from 'node:url'

/** Tools whose `command` argument is a shell command line. */
const SHELL_TOOLS = new Set(['pwsh', 'bash', 'shell'])

/**
 * Checked against EVERY string value in the argument tree, whatever the tool.
 * Catches a credential pasted into a shell command, a file body, or a URL.
 */
const VALUE_RULES = [
  {
    id: 'credential',
    // sk-… (DeepSeek/OpenAI), ghp_/gho_/… (GitHub), AKIA… (AWS), xox?-… (Slack)
    pattern: /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,})\b/,
    reason: '疑似凭据明文出现在工具参数里',
    hint: '从凭据存储或环境变量读出来传 header，不要把它写进命令文本。',
  },
]

/**
 * Checked against a shell command line only. Patterns are anchored on a command
 * boundary so an incidental mention inside a string literal stays quiet.
 */
const SHELL_RULES = [
  {
    id: 'service',
    pattern: /(?:^|[\s;|&(`])(?:Stop-Service|Set-Service|Restart-Service|sc(?:\.exe)?\s+(?:stop|config|delete|create))\b/i,
    reason: '停止 / 修改 / 删除服务或驱动',
    hint: '停内核驱动类服务可能整机断网。先报告根因与回滚方案，由用户在管理员终端执行。',
  },
  {
    id: 'elevation',
    pattern: /Start-Process\b[^\n]*?-Verb\s+RunAs|\brunas(?:\.exe)?\b/i,
    reason: '自我提权，会脱离沙箱、审批账本与环境变量',
    hint: '需要管理员权限时停下来说明需要什么权限，由用户自己开终端。',
  },
  {
    id: 'registry',
    pattern: /\breg(?:\.exe)?\s+add\s+HKLM\b|New-ItemProperty\b[^\n]*HKLM:/i,
    reason: '写 HKLM 注册表',
    hint: '机器级注册表改动不可逆且影响全用户，需用户明确同意并留备份。',
  },
  {
    id: 'network',
    pattern: /\bnetsh\b[^\n]*(?:advfirewall|firewall)|\bSet-DnsClientServerAddress\b/i,
    reason: '改防火墙规则或系统 DNS',
    hint: '本机曾因切系统 DNS 导致会话中断；诊断只读，修复交用户决定。',
  },
  {
    id: 'driver',
    pattern: /\bpnputil(?:\.exe)?\b[^\n]*\/delete-driver/i,
    reason: '删除驱动包',
    hint: '卸载/回滚驱动需用户确认，并先留带时间戳的备份。',
  },
]

/** Collect every string value in an argument tree, bounded against cycles. */
function collectStrings(value, out = [], depth = 0) {
  if (depth > 8 || value === null || value === undefined) return out
  if (typeof value === 'string') {
    out.push(value)
    return out
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out, depth + 1)
    return out
  }
  if (typeof value === 'object') {
    for (const item of Object.values(value)) collectStrings(item, out, depth + 1)
  }
  return out
}

/** The command line a shell tool would run, or '' for any other tool. */
function shellText(name, args) {
  if (!SHELL_TOOLS.has(name) || !args || typeof args !== 'object') return ''
  const parts = [args.command, args.cmd, args.script]
    .filter((part) => typeof part === 'string')
  return parts.join('\n')
}

/** Turn a matched rule into the ask decision the runtime expects. */
function ask(rule, evidence) {
  return {
    kind: 'ask',
    reason: `[agent-guard:${rule.id}] ${rule.reason} → ${rule.hint} 命中片段：${evidence}`,
    displayReason: {
      en: `agent-guard blocked on rule "${rule.id}": ${rule.reason}`,
      zh: `agent-guard 规则「${rule.id}」命中：${rule.reason}`,
    },
  }
}

/** Short, single-line excerpt of the offending text for the prompt. */
function excerpt(text, match) {
  const start = Math.max(0, match.index - 30)
  const end = Math.min(text.length, match.index + match[0].length + 30)
  const slice = text.slice(start, end).replace(/\s+/g, ' ')
  // Never echo the secret itself back into the prompt or the transcript.
  return slice.replace(match[0], `${match[0].slice(0, 4)}…${match[0].slice(-2)}`)
}

/**
 * Decide on one tool call.
 * @param {{ name: string, arguments?: unknown }} execution
 * @returns {{ kind: 'ask', reason: string, displayReason: object } | undefined}
 *   undefined means "no rule matched, let the call proceed".
 */
export function check(execution) {
  const name = String(execution?.name ?? '')
  const args = execution?.arguments

  for (const text of collectStrings(args)) {
    for (const rule of VALUE_RULES) {
      const match = rule.pattern.exec(text)
      if (match) return ask(rule, excerpt(text, match))
    }
  }

  const command = shellText(name, args)
  if (command) {
    for (const rule of SHELL_RULES) {
      const match = rule.pattern.exec(command)
      if (match) return ask(rule, excerpt(command, match))
    }
  }

  return undefined
}

export function apply(ctx) {
  ctx.inject(['tools'], (scoped) => {
    scoped.on('tools/pre-execute', async (execution, next) => check(execution) ?? next())
  })
}

/** Self-check: `node lib/index.js`. Fails loudly if a rule stops firing. */
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cases = [
    // [label, execution, expected rule id or null]
    ['clean command', { name: 'pwsh', arguments: { command: 'Get-ChildItem C:\\' } }, null],
    ['read-only service query', { name: 'pwsh', arguments: { command: 'sc.exe query SmartDNS' } }, null],
    ['stop service', { name: 'pwsh', arguments: { command: 'Stop-Service SmartDNS' } }, 'service'],
    ['sc config', { name: 'pwsh', arguments: { command: 'sc.exe config Foo start= disabled' } }, 'service'],
    ['service name in a string literal', { name: 'pwsh', arguments: { command: 'Write-Host "Stop-Service is forbidden"' } }, null],
    ['elevation', { name: 'pwsh', arguments: { command: 'Start-Process pwsh -Verb RunAs' } }, 'elevation'],
    ['hk registry', { name: 'pwsh', arguments: { command: 'reg.exe add HKLM\\Software\\X /v a /d b' } }, 'registry'],
    ['dns change', { name: 'pwsh', arguments: { command: 'Set-DnsClientServerAddress -InterfaceIndex 5 -ServerAddresses 1.1.1.1' } }, 'network'],
    ['secret in command', { name: 'pwsh', arguments: { command: 'curl -H "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz"' } }, 'credential'],
    ['secret in a file body', { name: 'write', arguments: { file_path: 'x.txt', content: 'token=ghp_0123456789abcdefghijABCDEFGHIJ' } }, 'credential'],
    ['nested secret', { name: 'pwsh', arguments: { command: 'x', env: { K: 'AKIAIOSFODNN7EXAMPLE' } } }, 'credential'],
  ]

  let failed = 0
  for (const [label, execution, expected] of cases) {
    const decision = check(execution)
    const actual = decision ? /\[agent-guard:([a-z]+)\]/.exec(decision.reason)[1] : null
    const ok = actual === expected
    if (!ok) failed += 1
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: expected ${expected ?? 'allow'}, got ${actual ?? 'allow'}`)
    if (decision && /sk-abcdefghijklmnopqrstuvwxyz/.test(decision.reason)) {
      failed += 1
      console.log('FAIL secret echoed verbatim into the ask reason')
    }
  }
  console.log(failed === 0 ? '\nall checks passed' : `\n${failed} check(s) failed`)
  process.exitCode = failed === 0 ? 0 : 1
}
