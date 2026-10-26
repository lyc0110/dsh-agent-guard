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
 *
 * Scope rule: a pattern may encode a shell-level invariant (a program name, a
 * subcommand, a flag). It may NEVER encode a fact about one machine — no host
 * aliases, no drive letters, no service names. Those live in AGENTS.md, where
 * the model reads them per workspace.
 */

export const name = 'agent-guard'

import { fileURLToPath } from 'node:url'

/**
 * Tools whose `command` argument is a shell command line.
 * `ops_bash` is this harness's bash executor (dsh-ops); `bash` / `shell` are
 * kept for harnesses that name the tool plainly. Getting this set wrong is
 * silent: shellText() returns '' and every SHELL_RULE is skipped.
 */
const SHELL_TOOLS = new Set(['pwsh', 'ops_bash', 'bash', 'shell'])

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
 *
 * Cross-shell note: the same intent has different spellings in PowerShell and
 * POSIX shell, so most rules list both. Two MSYS specifics are folded in —
 * (1) a native Windows program's `/flag` gets rewritten into a path, so bash
 * users must write `//flag`; (2) quoting a key path is the bash norm, so the
 * registry rule tolerates quotes around the hive.
 */
const SHELL_RULES = [
  {
    id: 'service',
    pattern: /(?:^|[\s;|&(`])(?:systemctl\s+(?:stop|restart|disable|mask|kill)|service\s+[\w.@-]+\s+(?:stop|restart|disable)|Stop-Service|Set-Service|Restart-Service|sc(?:\.exe)?\s+(?:stop|config|delete|create)|net\s+stop)\b/i,
    reason: '停止 / 修改 / 删除服务或驱动',
    hint: '停内核驱动类服务可能整机断网。先报告根因与回滚方案，由用户在管理员终端执行。',
  },
  {
    id: 'elevation',
    // Narrow on purpose. The consequence that matters is landing in a
    // PERSISTENT root shell — every later command is then outside this gate's
    // view. A one-shot `sudo apt install` is routine, and whatever it actually
    // does is already covered by its own rule (see `service`: `sudo systemctl
    // restart` lands on `service`, not here). Flagging bare sudo would just
    // train the user to click through.
    //
    // -i / -s / su / bash / sh / zsh = get a shell. `sudo -S bash` (password on
    // stdin, no TTY) is the realistic agent path and lands on `bash`.
    // NOTE: `-l` is deliberately absent — `sudo -l` is --list, a read-only
    // privilege query; `--login` is `-i`.
    // The leading group absorbs option tokens, including ones that take a
    // value (-u root), so both `sudo -u root -i` and `sudo -i -u root` match.
    pattern: /(?:^|[\s;|&(`])(?:Start-Process\b[^\n]*?-Verb\s+RunAs|runas(?:\.exe)?\b|gsudo\b|pkexec\b|sudo\s+(?:(?:-[ugpC]\s+[^\s;|&]+|-[A-Za-z]+)\s+)*(?:-i\b|-s\b|su\b|bash\b|sh\b|zsh\b)|doas\s+(?:(?:-u\s+[^\s;|&]+|-[A-Za-z]+)\s+)*(?:-s\b|su\b|bash\b|sh\b|zsh\b))/i,
    reason: '自我提权 / 取得常驻 root shell，会脱离沙箱与审批账本',
    hint: '需要管理员权限时停下来说明需要什么权限，由用户自己开终端。',
  },
  {
    id: 'registry',
    pattern: /\breg(?:\.exe)?\s+add\s+["']?HKLM\b|\bNew-ItemProperty\b[^\n]*HKLM:/i,
    reason: '写 HKLM 注册表',
    hint: '机器级注册表改动不可逆且影响全用户，需用户明确同意并留备份。',
  },
  {
    id: 'network',
    pattern: /\bnetsh\b[^\n]*(?:advfirewall|firewall|set\s+(?:dns|dnsservers))|\bSet-DnsClientServerAddress\b|\bresolvectl\s+(?:dns|domain|revert)\b|\bnmcli\s+(?:connection|networking|device)\s+(?:modify|delete|down)\b|\bip\s+route\s+(?:add|del|replace|flush)\b/i,
    reason: '改防火墙规则或系统 DNS / 路由',
    hint: '本机曾因切系统 DNS 导致会话中断；诊断只读，修复交用户决定。',
  },
  {
    id: 'driver',
    // `/{1,2}`: bash must write `//delete-driver`, PowerShell ` /delete-driver`.
    pattern: /\bpnputil(?:\.exe)?\b[^\n]*\/{1,2}(?:delete-driver|remove-driver)/i,
    reason: '删除驱动包',
    hint: '卸载/回滚驱动需用户确认，并先留带时间戳的备份。',
  },
]

/**
 * A segment that only reads. Skipped by SHELL_RULES so that searching a repo
 * for "systemctl stop" — including searching this plugin's own source — does
 * not fire the gate. Applied per segment, never to a whole command line, so
 * `grep x; Stop-Service y` still catches the second half.
 */
const READ_ONLY_SEGMENT = /^\s*(?:(?:grep|rg|ag|ack|findstr|Select-String|sls|man|less|more|Get-Help|Get-Content|Get-ChildItem|cat|head|tail|wc|type|which|whereis|command)\b|git\s+(?:log|grep|show|diff)\b)/i

/** ssh options that take their value as the next token. */
const SSH_VALUE_OPTS = /^-[bcDEeFIiJLlmOopQRSWw]$/

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

/**
 * Split a command line into the units a shell would actually run. Rules are
 * matched per segment, which is what makes the read-only exemption safe.
 */
function segments(command) {
  return command.split(/[;\n]|&&|\|\||\|/)
}

/** Quote-aware, expansion-free token split. Enough to find an ssh host. */
function tokenize(segment) {
  const tokens = []
  let current = ''
  let quote = ''
  let has = false
  for (const ch of segment) {
    if (quote) {
      if (ch === quote) quote = ''
      else current += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      has = true
      continue
    }
    if (/\s/.test(ch)) {
      if (has || current) tokens.push(current)
      current = ''
      has = false
      continue
    }
    current += ch
  }
  if (has || current) tokens.push(current)
  return tokens
}

/**
 * The remote command string carried by an `ssh` invocation, or '' if this
 * segment is not one. Generic: it reads the grammar of ssh (options, then host,
 * then a command), not any particular host alias.
 */
function sshRemoteCommand(segment) {
  const tokens = tokenize(segment)
  let i = 0
  // Skip a wrapper that stays in the same shell.
  while (i < tokens.length && /^(?:sudo|env|time|timeout)$/.test(tokens[i])) {
    i += 1
    if (i < tokens.length && /^-[A-Za-z]+$/.test(tokens[i])) i += 1
    while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i += 1
  }
  if (!tokens[i] || tokens[i] !== 'ssh') return ''
  i += 1
  while (i < tokens.length) {
    const token = tokens[i]
    if (token === '--') {
      i += 1
      break
    }
    if (!token.startsWith('-')) break
    i += SSH_VALUE_OPTS.test(token) ? 2 : 1
  }
  if (i >= tokens.length) return ''
  return tokens.slice(i + 1).join(' ')
}

/** Apply SHELL_RULES to one command string, following ssh one hop deeper. */
function checkShell(command, depth = 0) {
  for (const segment of segments(command)) {
    if (READ_ONLY_SEGMENT.test(segment)) continue
    for (const rule of SHELL_RULES) {
      const match = rule.pattern.exec(segment)
      if (match) return ask(rule, excerpt(segment, match))
    }
    if (depth < 2) {
      const remote = sshRemoteCommand(segment)
      if (remote) {
        const decision = checkShell(remote, depth + 1)
        if (decision) return decision
      }
    }
  }
  return undefined
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
  // Never echo the secret itself back into the prompt or the transcript.
  const masked = `${match[0].slice(0, 4)}…${match[0].slice(-2)}`
  const slice = text.slice(start, match.index) + masked + text.slice(match.index + match[0].length, end)
  return slice.replace(/\s+/g, ' ')
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
    const decision = checkShell(command)
    if (decision) return decision
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

    // — bash side (ops_bash). These all passed silently through 0.1.0. —
    ['ops_bash: stop service', { name: 'ops_bash', arguments: { command: 'Stop-Service SmartDNS' } }, 'service'],
    ['ops_bash: systemctl stop', { name: 'ops_bash', arguments: { command: 'systemctl stop nginx' } }, 'service'],
    ['ops_bash: systemctl mask', { name: 'ops_bash', arguments: { command: 'systemctl mask firewalld' } }, 'service'],
    ['ops_bash: systemctl status is fine', { name: 'ops_bash', arguments: { command: 'systemctl status nginx' } }, null],
    ['ops_bash: pnputil double slash', { name: 'ops_bash', arguments: { command: 'pnputil //delete-driver oem12.inf //uninstall' } }, 'driver'],
    ['ops_bash: pnputil single slash', { name: 'ops_bash', arguments: { command: 'pnputil /delete-driver oem12.inf' } }, 'driver'],
    ['ops_bash: quoted HKLM', { name: 'ops_bash', arguments: { command: 'reg.exe add "HKLM\\Software\\X" //v a //d b' } }, 'registry'],
    ['ops_bash: netsh set dns', { name: 'ops_bash', arguments: { command: 'netsh interface ipv4 set dns name=Ethernet static 1.1.1.1' } }, 'network'],
    ['ops_bash: interactive sudo', { name: 'ops_bash', arguments: { command: 'sudo -i' } }, 'elevation'],
    ['ops_bash: sudo bash', { name: 'ops_bash', arguments: { command: 'sudo bash' } }, 'elevation'],
    ['ops_bash: bare sudo install is quiet', { name: 'ops_bash', arguments: { command: 'sudo apt-get install -y jq' } }, null],
    ['ops_bash: sudo -l is a read-only query', { name: 'ops_bash', arguments: { command: 'sudo -l' } }, null],
    ['ops_bash: sudo -u root -i', { name: 'ops_bash', arguments: { command: 'sudo -u root -i' } }, 'elevation'],
    ['ops_bash: sudo -i -u root', { name: 'ops_bash', arguments: { command: 'sudo -i -u root' } }, 'elevation'],
    ['ops_bash: sudo -H -i', { name: 'ops_bash', arguments: { command: 'sudo -H -i' } }, 'elevation'],
    ['ops_bash: doas -s', { name: 'ops_bash', arguments: { command: 'doas -s' } }, 'elevation'],
    ['ops_bash: plain su is not gated', { name: 'ops_bash', arguments: { command: 'su -' } }, null],
    ['ops_bash: commands inside $( )', { name: 'ops_bash', arguments: { command: 'echo $(sudo -i)' } }, 'elevation'],
    ['ops_bash: ssh remote stop', { name: 'ops_bash', arguments: { command: 'ssh laptop-linux "sudo systemctl stop nginx"' } }, 'service'],
    ['ops_bash: ssh with options', { name: 'ops_bash', arguments: { command: 'ssh -p 22 -i key host systemctl disable nginx' } }, 'service'],
    ['ops_bash: ssh with a benign command', { name: 'ops_bash', arguments: { command: 'ssh host uptime' } }, null],
    ['ops_bash: read-only grep is quiet', { name: 'ops_bash', arguments: { command: 'grep -rn "systemctl stop" docs/' } }, null],
    ['ops_bash: rg over own source is quiet', { name: 'ops_bash', arguments: { command: "rg 'pnputil' lib/" } }, null],
    ['ops_bash: grep then stop still fires', { name: 'ops_bash', arguments: { command: 'grep x README.md; systemctl stop nginx' } }, 'service'],
    ['ops_bash: grep && stop still fires', { name: 'ops_bash', arguments: { command: 'grep -q x f && Stop-Service y' } }, 'service'],
  ]

  let failed = 0
  for (const [label, execution, expected] of cases) {
    const decision = check(execution)
    const actual = decision ? /\[agent-guard:([a-z]+)\]/.exec(decision.reason)[1] : null
    const ok = actual === expected
    if (!ok) failed += 1
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: expected ${expected ?? 'allow'}, got ${actual ?? 'allow'}`)
    if (decision && /sk-[A-Za-z0-9]{20,}/.test(decision.reason)) {
      failed += 1
      console.log('FAIL secret echoed verbatim into the ask reason')
    }
  }
  console.log(failed === 0 ? `\nall ${cases.length} checks passed` : `\n${failed} check(s) failed`)
  process.exitCode = failed === 0 ? 0 : 1
}
