# 服务器校时分析与修复

本次分析对象为 ARM64 `libswiftMetal_patched.dylib`，SHA-256：
`447792aacd73cec65cb850da86e39f8915cdd6526424874016e2ed0c44c9bc69`；
Mach-O UUID：`79AE6B44-7FE2-3C31-9765-09ED0C83C298`。
以下均为 image base 为 0 的静态地址。其他版本需要重新核对。

## 实际调用链

```text
-[pytpiutoideidcs pp8364bd3d44cf] 0x895950
  → sub_895F50 / sub_8975BC
  → +[potpiutoideidcs mnzqplxkcvbasd] 0xeb5dd8：读取配置的时间主机
  → 格式化 http://%@/wx/get_time
  → +[WCTools requestServerTime:com:] 0x605cac
  → NSURLSession dataTaskWithRequest:completionHandler:
  → GET /wx/get_time → resume
  → 响应回调 0x607718 / 解析片段 sub_608A2C
  → 上层校时回调 0x897a64
  → setL_s_time_interval:
```

| 证据 | 地址和含义 |
| --- | --- |
| 业务调用点 | `0x896038` 直接调用 WCTools；`0x8976d4` 经混淆 wrapper 调用 |
| 时间 URL | CFString `0x1639db0`，数据 `0x1639d90`；写入指令 `0x8967dc` 至 `0x896908` 恢复出 `http://%@/wx/get_time` |
| 配置 getter | `0xeb5dd8` 读取全局 `0x179f748` |
| 请求方法 | CFString `0x15a7d30` 恢复为 `GET`，写入点 `0x606b48`、`0x606b58`、`0x606b68` |
| 网络创建 | `0x606548`、`0x6072b8`；使用 default session configuration，清空 `connectionProxyDictionary`，再创建并执行 task |
| 响应字段 | CFString `0x15a7d70` 为 `timestamp`，`0x15a7d90` 为 `time` |
| JSON 解析 | `0x608a80` 解析；`0x608aa4` 读取 timestamp 并取 double；`0x608aec` 读取 time；`0x608b04` 将 timestamp 除以 1000 转为秒 |

已跟踪的请求构造没有显式请求体，URL 模板没有查询参数。
这不等于已通过设备抓包验证全部最终请求头。普通代理看不到请求也不能证明
请求没有发出，因为此处明确清空代理配置。

## 时间偏移计算

上层响应处理在 `0x898014` 先将 `l_s_time_interval` 设为 0，
记录收到响应时的本地 NSDate 秒值。在 `0x8980d8` 计算本地收发时间差，
后续要求服务器时间大于 0，且往返耗时小于 0.5 秒。

`sub_898934` 中 `0x89899c` 附近的运算为：

```text
serverSeconds - laterLocalNow + receiveLocalNow - requestStart
```

之后还会比较 `wc_howLong / 1000.0`；`sub_899350` 的 `0x8993ec`
将结果写入 `setL_s_time_interval:`。以上不能简化成标准的 RTT/2 校时算法。
修复保留这段原始运算，不自行生成 timestamp，也不替换成本机时间。

## LeanCloud 时间接口的证据边界

`+[LCApplication getServerDate:]` 位于 `0x11ce714`，其 SDK 实现确实会发起
GET `/1.1/date` 并解析 `iso`。但 `_objc_msgSend$getServerDate:`（`0x1263e20`）
只有 `0x11cec74` 和 `0x11ceda4` 两处 SDK 内部 wrapper 调用；对应 selector 引用
`0x1417250`、`0x141a4e8`、`0x141a4f0` 未找到业务校时调用。

因此不将 `/1.1/date` 当作已证实的校时备用接口，也不为它增加网络例外。
LeanCloud 本身存在业务初始化/上报引用；上述结论不代表整个 SDK 未使用。
静态分析仍无法排除动态生成 selector、外部模块或未恢复的混淆路径。

## 修复规则

1. 在样本自身的 `WCTools +requestServerTime:com:` 入口观察完整地址，
   原样转交原始方法、参数与 completion；安装前校验 Objective-C 方法 ABI。
   如果首次校时发生在观察器安装竞态窗口，已识别的样本 UUID 中，
   WCTools/订单校时调用栈也可触发同样的严格请求检查，并给任务打一次性校时标记。
2. 只登记 HTTP/HTTPS 的严格 `/wx/get_time` 地址；保留协议、主机和端口，
   拒绝 userinfo、query、fragment、大小写路径变体和编码路径变体。
3. 请求必须命中已观察地址，且为无 body、无 body stream 的 GET。
   upload task 接口可能另行提供 payload，因此不提供校时例外。
   仅路径相同不会获得例外，不会把整个 session 加入允许列表。
4. 创建 task 和 `resume` 使用同一请求规则；原有拒绝标记仍优先取消任务。
   同一 session 后续 `/wx/receive_data_dy`、`/operate` 等上报继续受拦截。

## 验证范围

- C 测试：域名边界与路径精确匹配。
- macOS Foundation 测试：WCTools 原参数转发、重复安装、完整地址及方法/body
  边界；使用内存 URLProtocol 真正执行普通和私有 session 的校时 task，
  并验证同一 session 的上报任务不进入 fixture。
- Python 测试：增加主插件依赖时保留代码、数据和现有库序号。
- CI：执行上述测试、编译 iOS ARM64 hook、签名并校验产物。

这些测试不执行实际主插件。手机端功能、真实响应、往返耗时、最终偏移和
毫秒级精度尚需实测；没有 USB 设备连接时不把离线结果当作设备验证。
校时需要访问原服务器，服务器仍可看到连接和 IP，不能保证作者完全不可见。
