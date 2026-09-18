# DYYCHUnlock

当前仓库只维护一个修复版本，输出 `libDYYCHUnlock.dylib`。
保留已使用 v8 的兼容逻辑，新增对已确认的订单、账号、设备、消息、推送和心跳上报链路的拦截。

## 构建

Push 到 `main` 或手动运行 GitHub Actions 的 `build-dyychu`。
下载唯一产物 `DYYCHUnlock-fixed-arm64`。

## 使用

1. 使用新 `libDYYCHUnlock.dylib` 替换旧 v8/v9 Hook，不要同时加载新旧版本。
2. patched 主插件需要先加载此 Hook。包内 `prepare_private_copy.py` 可以为指定样本创建带依赖的新副本，原文件保持不变。
3. 主插件副本与 Hook 在 App 内必须位于同一目录；通过注入工具重新签名。不要同时注入原主插件和新副本。
4. 验证冷启动、正常操作和测试订单事件，并检查设备或网关流量。

支持的样本 SHA-256：
`447792aacd73cec65cb850da86e39f8915cdd6526424874016e2ed0c44c9bc69`

完整链路和证据见 [PRIVACY.md](PRIVACY.md)。构建通过不等于手机端功能与断连都已经验证；远程依赖功能需要实机确认。

## 文件

- `src/DYYCHUnlock.m`：保留的 v8 兼容逻辑及样本检查。
- `src/PrivacyShield.m`：上报入口、网络任务与 WebSocket 拦截。
- `src/PrivacyPolicy.h`：域名规则。
- `tests/`：策略、回调和加载依赖测试。
- `prepare_private_copy.py`：为主插件副本增加启动依赖。
