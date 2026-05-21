# DYYCHUnlock

抖音演唱会助手全功能解锁 dylib。通过 TrollFools 注入抖音，无需 PC、无需 frida。

## 功能

1. **Fake WS** — hook SRWebSocket，本地回 heartbeat_ack
2. **Gate 解锁** — `_open_dy_ych_show = 1`
3. **addBtn fix** — 补 addSubview 让按钮可见
4. **Network hook** — 触发 req_finish 建演唱会菜单

## 编译

Push 到 GitHub → Actions 自动编译 → 下载 `libDYYCHUnlock.dylib`

## 使用

1. 下载 `libDYYCHUnlock.dylib`
2. TrollFools 注入到抖音 Aweme.app
3. 打开抖音 → 进演唱会页 → 点我抢 → 菜单自动弹出
