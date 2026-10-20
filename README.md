# dsh-agent-guard

DSH 的 `tools/pre-execute` 门禁：在工具真正执行前，把**可机械判定**的危险调用拦下来，交给用户决定。

它不试图做语义判断。像「诊断和修复要分开」「用户没提问先别动手」这类规则，任何正则都判不准，仍然只能写在 `AGENTS.md` 里靠模型自觉。这个插件只管那些一眼能看出来、也不该指望模型每次都记住的部分。

## 装

本包不走 npm（`private: true`，防误发）。两种分发方式：

**本地目录**——在 DSH 里用 `plugin_manager` 的 `install_bundle`，target 填 `file:D:\AgentGeneralWorkSpace\tools\dsh-agent-guard`。

**Git 仓库**——把仓库地址加进 profile 的依赖（`pnpm add dsh-agent-guard@git+https://…`），再把 `dsh-agent-guard` 加进 `dsh.profile.bundles`。

**装完必须重启 DSH。** host 插件代码不做热重载，改了文件不重启等于没改。

本机额外做了一步：`~/.dsh/profiles/desktop/node_modules/dsh-agent-guard` 已经是指向本仓库的目录联接，所以改完源码只需重启，不必重新安装。如果哪次 `pnpm install` 把联接冲掉、变回实体副本，重跑一次 `install_bundle` 即可。

## 拦什么

所有规则都返回 `ask`，从不硬性 `deny`——你看得到命中的是哪条、命中了什么，然后自己决定放不放。没有可用审批器时按框架规则会降级为拒绝，方向是安全的。

| 规则 | 触发条件 | 作用范围 |
|---|---|---|
| `credential` | 参数里出现 `sk-…`（16 位以上）、`ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`、`AKIA…`、`xox?-…` | **任意工具**的任意字符串参数，含嵌套对象和数组 |
| `service` | `Stop-Service`、`Set-Service`、`Restart-Service`、`sc.exe stop\|config\|delete\|create` | 仅 shell 命令行 |
| `elevation` | `Start-Process … -Verb RunAs`、`runas` | 仅 shell 命令行 |
| `registry` | `reg.exe add HKLM…`、`New-ItemProperty … HKLM:` | 仅 shell 命令行 |
| `network` | `netsh … advfirewall\|firewall`、`Set-DnsClientServerAddress` | 仅 shell 命令行 |
| `driver` | `pnputil /delete-driver` | 仅 shell 命令行 |

shell 规则按命令边界锚定，所以 `Write-Host "Stop-Service is forbidden"` 这种把命令名写在字符串里的情况不会误报。

凭据命中时，弹窗里的片段会把密钥打码成 `sk-a…yz`，不会把明文再送回对话记录。

## 调

规则表就是 `lib/index.js` 顶部的 `VALUE_RULES` 和 `SHELL_RULES`，纯正则，直接改。改完跑一遍自检，再重启 DSH。

## 自检

```bash
node lib/index.js
```

跑 11 个用例，覆盖每条规则的命中与不命中（含上面那条字符串字面量的对照）。改规则后跑一遍，别只信正则写得对。

## 已知边界

- 只看工具参数，看不到你在对话里打了什么字。
- 只认得写死的模式。自己拼出来的等价命令（比如 `& 'Stop-Service'`、变量拼出来的服务名）拦不住。
- 短于门槛的 `sk-10086` 这类占位符不会触发，避免天天弹窗。

## License

MIT
