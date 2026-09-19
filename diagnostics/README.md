# 可选的实机校时诊断

`server_time_probe.js` 用于定位一次校时在哪个环节停止。它只适用于已分析的旧主插件，
Mach-O UUID 必须为 `79AE6B44-7FE2-3C31-9765-09ED0C83C298`。
原 patched 文件与仅增加加载依赖的 private 副本拥有同一个 UUID；UUID 无法区分这两份文件，
也不能代替已安装文件的 SHA-256 校验。脚本另外列出进程实际加载的 Hook 名称和 UUID。

脚本不会主动发起请求、取消任务、替换服务器响应、改时间值或改隐私策略。
它观察 WCTools、固定配置 GET 和已观察到的完整校时地址。包装 completion 时先用原参数调用原 completion，
返回后才在 `finally` 中记录结果，避免先做日志/JSON 检查再进入原校时计算。回调对象保留至执行完成；最多跟踪 512 个待完成回调/任务。
记录上限命中会产生 `probe-capacity`，此后部分回调可能没有日志。

插桩、JSON 检查和日志会扰动耗时，可能影响样本的 0.5 秒 RTT 判断。
**这份日志只能验证链路，不能用于证明毫秒级精度。** 完成诊断后退出 Frida、彻底关闭并重开 App，
再做不带插桩的功能/精度测试。不要在还有待完成回调时卸载或热重载脚本。

## 运行

需要手机端 Frida 与电脑端版本兼容，以及可用的 Objective-C bridge。
使用 `frida-tools` CLI；如果通过自写 Python `create_script` 运行且 `ObjC` 不存在，
需要先用 `frida-compile` 打包 `frida-objc-bridge`。脚本遇到缺失 bridge 会报告 `unavailable`。

在仓库目录中执行（将占位符替换为实际 App 的 bundle identifier）：

```powershell
frida-ps -Uai
frida -U -f "<APP_BUNDLE_ID>" -l .\diagnostics\server_time_probe.js -o .\server-time-probe.log
```

优先从冷启动开始，以观察早期配置请求。如果已运行，也可以按 PID 附加：

```powershell
frida -U -p <PID> -l .\diagnostics\server_time_probe.js -o .\server-time-probe.log
```

附加到已有进程可能错过配置、校时入口和任务创建；没有对应日志不能证明它们没有发生。
Frida CLI 是否暂停新进程取决于所用版本；若提示进程暂停，在 CLI 中执行 `%resume` 后正常操作 App。
日志文件请放在本地诊断目录，勿提交仓库。

## 日志判读

| 事件 | 说明 |
| --- | --- |
| `module` | 实际加载的主插件/Hook 名称、UUID；不输出 App 沙箱完整路径 |
| `method-state` | 当前 WCTools IMP 归属；若是 Objective-C block trampoline，也记录 block invoke 所属模块 |
| `time-host-getter` | 配置时间主机是否为字符串、是否能组成预期地址；主机以 `server-N` 代号表示 |
| `clock-entry` | 原校时入口是否执行、URL 形状是否符合 `/wx/get_time`，以及是否有 completion |
| `task-create` / `task-return` | 校时或固定配置请求是否创建；返回任务的 URL 是否被替换为本地拒绝 scheme |
| `task-resume` / `task-cancel` | 已跟踪任务被调用 resume/cancel 时的状态与脱敏请求形状 |
| `transport-completion` | 原 completion 的 NSError code、HTTP status、字节数和 JSON 是否有顶层 `timestamp`；不输出正文 |
| `clock-completion` | WCTools 返回的服务器秒值及有限/正数检查；不输出时间字符串 |
| `time-offset-written` | setter 返回后 `_l_s_time_interval` 的实际秒值；0 的重置和后续非零值都记录 |

任务 state 的标准值为 0=running、1=suspended、2=canceling、3=completed。
`method-state.status=original-target-imp` 表示当时仍指向样本原方法；
`DYYCHUnlock-block-observer` 表示 block invoke 位于名称含 DYYCHUnlock 的模块；
其他替换或未知 trampoline 明确标为 `replaced-or-forwarded-imp`，不据此断言隐私 Hook 已安装。
重命名后的 Hook 可能无法按名称识别，要结合模块 UUID、安装目录文件哈希和实际事件判断。

固定配置范围只有：
`https://m1.apifoxmock.com/m1/2877214-1694412-default/xx/api/_conf/v1`。
校时只跟踪进入本样本 WCTools 后观察到的完整 HTTP(S) `/wx/get_time` 地址。
不会保存或输出其他请求的账号、头、cookie、查询参数和正文，也不会输出配置响应正文。
为处理 Foundation 类簇，脚本在 NSURLSession 及运行时子类入口放置探针，
但只有上述范围内的请求会被记录、包装 completion 和关联任务。

当前仅完成 JavaScript 语法检查；没有据此声称已在手机动态验证。
