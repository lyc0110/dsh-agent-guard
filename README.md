# dsh-agent-guard

DSH 的 `tools/pre-execute` 门禁：在工具真正执行前，把**可机械判定**的危险调用拦下来，交给用户决定。

它不试图做语义判断。像「诊断和修复要分开」「用户没提问先别动手」这类规则，任何正则都判不准，仍然只能写在 `AGENTS.md` 里靠模型自觉。这个插件只管那些一眼能看出来、也不该指望模型每次都记住的部分。

判定结果是 `ask`，不是 `deny`：你看得到命中的是哪条规则、命中了什么，然后自己决定放不放。没有可用审批器时按框架规则降级为拒绝，方向是安全的。

## 装

本包不走 npm（`private: true`，防误发）。两种分发方式：

**本地目录**——用 `plugin_manager` 的 `install_bundle`，target 填 `file:/绝对路径/dsh-agent-guard`。

**Git 仓库**——把仓库地址加进 profile 依赖，再把 `dsh-agent-guard` 加进 `dsh.profile.bundles`。

**装完必须重启 DSH。** host 插件代码不做热重载，改了文件不重启等于没改。

开发时可以把 `node_modules/dsh-agent-guard` 做成指向源码目录的目录联接（Windows）或符号链接，这样改完源码只需重启，不必重新安装。如果哪次 `pnpm install` 把链接冲掉、变回实体副本，重跑一次 `install_bundle`。

## 拦什么

| 规则 | 触发条件 | 作用范围 |
|---|---|---|
| `credential` | 参数里出现 `sk-…`（16 位以上）、`ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`、`AKIA…`、`xox?-…` | **任意工具**的任意字符串参数，含嵌套对象和数组 |
| `service` | `systemctl stop\|restart\|disable\|mask\|kill`、`service <名> stop\|restart\|disable`、`Stop-Service`、`Set-Service`、`Restart-Service`、`sc[.exe] stop\|config\|delete\|create`、`net stop` | 仅 shell 命令行 |
| `elevation` | `Start-Process … -Verb RunAs`、`runas`、`gsudo`、`pkexec`、`sudo` 落到 shell（`-i`/`-s`/`su`/`bash`/`sh`/`zsh`）、`doas` 同构 | 仅 shell 命令行 |
| `registry` | `reg[.exe] add HKLM…`（键名可加引号）、`New-ItemProperty … HKLM:` | 仅 shell 命令行 |
| `network` | `netsh … advfirewall\|firewall`、`netsh … set dns`、`Set-DnsClientServerAddress`、`resolvectl dns\|domain\|revert`、`nmcli connection\|networking\|device modify\|delete\|down`、`ip route add\|del\|replace\|flush` | 仅 shell 命令行 |
| `driver` | `pnputil /delete-driver`、`pnputil /remove-driver`（单斜杠双斜杠都认） | 仅 shell 命令行 |

同时覆盖两套执行器的写法：PowerShell（`pwsh`）与 POSIX shell（`ops_bash`，以及别处可能叫 `bash`/`shell` 的同名工具）。同一条意图在两边拼法不同，规则里两种都列了。

`elevation` 是**按后果**收窄的：只拦"落进常驻 root shell"，不拦裸 `sudo`。`sudo apt-get install` 是常态，每次都弹窗只会训练用户无脑点确认；而它真正干了什么，已经被对应规则管住——`sudo systemctl restart nginx` 落在 `service` 上，不落在 `elevation` 上。

## 判定机制

**先切段再判。** 命令行按 `;`、换行、`&&`、`||`、`|` 切成 shell 真正会执行的段，逐段匹配。这样引用与 `$( )` 里的内容不会被当成段首。

**只读段豁免。** 段首是只读程序时跳过 shell 规则——`grep`、`rg`、`ag`、`ack`、`findstr`、`Select-String`、`sls`、`man`、`less`、`more`、`Get-Help`、`Get-Content`、`Get-ChildItem`、`cat`、`head`、`tail`、`wc`、`type`、`which`、`whereis`、`command`，以及 `git log|grep|show|diff`。所以在仓库里 `grep -rn "systemctl stop" .` 不会响，包括在本插件自己的源码上搜。

豁免是**段级**的，不是整条命令级：`grep x README.md; systemctl stop nginx` 的后半段照样拦，`grep -q x f && Stop-Service y` 同理。

**ssh 递归。** `ssh <host> <命令串>` 里 host 之后的命令串会被当作一条独立命令行，再走一遍同样的规则，最多两层。这是按 ssh 的语法读的——选项、host、命令——不认任何具体主机别名。所以 `ssh host "sudo systemctl stop nginx"` 命中 `service`。

**边界锚定。** 每条 shell 规则都以命令边界（空格、`;`、`|`、`&`、`(`、反引号、`{`）起头，所以 `Write-Host "Stop-Service is forbidden"` 这类把命令名写进字符串的情况不误报。

**凭据打码。** `credential` 命中时，弹窗里的片段会把密钥压成 `sk-a…yz`，不会把明文再送回对话记录。

## MSYS 的一个坑

在 Windows 上从 bash 调原生程序时，MSYS 会把单个 `/flag` 当路径改写掉（`/delete-driver` → `C:/Program Files/Git/delete-driver`），所以必须写 `//delete-driver`。规则里凡涉及斜杠参数的地方都接受 1～2 个斜杠。

## 调

规则表就是 `lib/index.js` 顶部的 `VALUE_RULES` 和 `SHELL_RULES`，外加只读段白名单 `READ_ONLY_SEGMENT`。纯正则，直接改。这个文件就是配置——没有 Config schema，也不打算有。

一条纪律：规则可以编码**与机器无关的 shell 层不变量**（程序名、子命令、标志位），不能编码**某台机器的事实**（主机别名、盘符、服务名）。后者属于 `AGENTS.md`，由模型按工作区上下文读。

## 自检

分两层，别混。

### 一、规则自检（自动，改完规则就跑）

```bash
node lib/index.js
```

36 个用例，覆盖每条规则的命中与不命中，以及几处容易写错的边界：字符串字面量不误报、只读段豁免、`grep; 危险命令` 不被豁免吃掉、`sudo -l` 是只读查询、`sudo -u root -i` 与 `sudo -i -u root` 两种语序都命中、`sudo apt-get install` 放行、ssh 远程命令递归。

它证明的是 `check()` 这个纯函数判断正确，**证明不了** runtime 真的把 `ask` 弹出去了。接线断了（工具名拼错、事件没挂上、插件没启用）这一层全过，门禁却一个都不响——0.1.0 就是这么错的。

### 二、端到端探针（手动，改完 `SHELL_TOOLS`、事件接线或插件安装方式后跑）

先重启 DSH（host 插件不热重载，改文件不重启等于没改），再让 agent 发这两条：

| 探针 | 期望 |
|---|---|
| `ops_bash: systemctl stop nginx; echo done` | 弹窗命中 `service`。同意后本机没有 `systemctl`（Windows/MSYS），`exit=127` |
| `ops_bash: ssh guard-probe.invalid "systemctl stop nginx"` | 弹窗命中 `service`（经 ssh 递归）。同意后 `Could not resolve hostname`，`exit=255` |

两条载荷都故意做成无害的：本机没有 nginx，`.invalid` 是保留域名、DNS 必然解析失败。**别拿真主机做探针**——`ssh somehost "sudo systemctl stop nginx"` 在门禁失效时会真的停掉对面的服务，那时候你是在用生产环境测门禁。

### 弹窗与否，只有人知道

这是本仓库最容易搞错的一点。`ask` 决策是送往 GUI 的，**不写进工具返回结果**：被拦下并经用户同意、和被放行直接执行，模型从自己的工具输出里看到的是同一个 `exit=127`、同一个 `exit=255`。模型既收不到"命中规则"的标记，也收不到"用户点了同意"的记录。

所以在交互过程中，**写门禁的模型对自己写的门禁是否生效是盲的**，它只能靠想象补齐。由此两条纪律：

- **别让模型自证门禁生效。** 上表的"期望"一列必须由人看着屏幕确认，或去 GUI 审批记录里查。模型说"已验证"，能指的只有 `node lib/index.js` 那 36 条。
- **模型说"没弹窗"时，先怀疑它的观察点。** 它本来就看不到弹窗，据此断言门禁失效，和断言门禁正常一样不可信。真要判定失效，用 `check()` 里临时写日志、或查审批记录这类模型能自己看见的证据。

实测记录（2026-10-27，Windows，DSH 重启后）：两条探针均弹出审批，用户确认，与上表一致。

## 已知边界

- 只看工具参数，看不到你在对话里打了什么字。
- 只认得写死的模式。拼接出来的等价命令拦不住：`"systemctl st""op x"`、`$CMD stop x`、`& 'Stop-Service'`、变量拼出来的服务名。
- ssh 递归受引号层数限制，`ssh host "systemctl st\"op x"` 这类多套一层的写法可能穿过。
- `ops_bash` 支持 `script_path` 直接执行脚本文件，门禁只看得到路径，看不到脚本内容。
- 凭据正则设了门槛，`sk-10086` 这类短占位符不会触发，避免天天弹窗。
- 不做语义判断：「诊断和修复要分开」「用户没明确要求别动手」这些仍然只能靠 `AGENTS.md`。
- **门禁是否真的弹窗，在工具结果里没有任何痕迹。** 模型在交互中感受不到自己被拦、也感受不到用户点了同意，判断只能由人做。详见「自检」最后一节。

## 故意不做的事

写下来是为了避免重复提议。

- **`rm -rf /`、`dd of=/dev/…`、`mkfs`**：AI 对应的规则是「删除前核实解析后的绝对路径」，那是语义判断，正则判不准；硬做只会把 `rm -rf node_modules dist` 一起误伤。而且宿主沙箱通常先拦住了，本机能拦到的大多是误报。真要收，应当等插件第一次长出配置项时作为可选规则出现。
- **裸 `su`**：无 TTY 时必然卡在密码提示上失败；真正能走通的非交互提权是 `sudo -S`，已被覆盖。
- **裸 `sudo <命令>`**：见上面 `elevation` 的说明，按后果而非按命令名拦。

## 变更记录

### 0.1.1

0.1.0 的 shell 规则在 bash 执行器上**完全没生效**——生效前提是工具名在白名单里，而清单里写的 `bash` 并不是实际工具名（实际是 `ops_bash`）。`shellText()` 返回空串，整张 `SHELL_RULES` 被静默跳过。这是本次修掉的主要缺陷。

- 修：`SHELL_TOOLS` 加入 `ops_bash`。
- 修：MSYS 双斜杠。`pnputil //delete-driver` 之前认不出。
- 修：`registry` 容忍引号包裹的键名（`reg.exe add "HKLM\..."`）。
- 修：`excerpt` 改为按偏移重建，不再用 `replace` 替换首个匹配，避免打码打错位置。
- 增：`service` 覆盖 `systemctl`、`service <名>`、`net stop`。
- 增：`network` 覆盖 `netsh … set dns`、`resolvectl`、`nmcli`、`ip route`。
- 增：`elevation` 收窄版交互提权（`sudo -i`/`-s`/`su`/`bash`、`doas`、`gsudo`、`pkexec`）。
- 增：ssh 远程命令递归判定。
- 增：只读段豁免，消除"在仓库里搜命令名就弹窗"的误报。
- 增：边界锚补反引号与 `{`。
- 自检用例从 11 条扩到 36 条。
- 文档：补端到端探针，写明"`ask` 不写进工具结果、弹窗只有人知道"，避免让模型自证门禁生效。

### 0.1.0

首个版本：`credential`、`service`、`elevation`、`registry`、`network`、`driver` 六条规则。

## License

MIT
