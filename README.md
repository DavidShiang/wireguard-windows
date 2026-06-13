a patch for WireGuard Dynamic Endpoint: Auto DNS Re-resolve After IP Change (No Scripts). 
官方没提供，脚本不优雅，补充了远端IP地址变化后，自动DDNS重连的功能。

新增功能：动态 IP 变更自动恢复 (Dynamic IP Recovery)

背景痛点：官方 wireguard-tools 及原生客户端在服务器对端 IP 变更后，无法自动触发 DNS 解析更新并重新建立连接。第三方脚本不够优雅可靠。
解决方案：直接在 WireGuard 的底层隧道服务（tunnel service）中，侵入式地实现一个轻量级的“看门狗（Watchdog）”，赋予其断网自愈的能力。当检测到对端超时3分钟后，系统会自动重新解析域名获取最新 IP，并尝试通过新的网络路径重建 WireGuard 隧道。
核心优势：
* 🔄 零手动干预：IP 变动后自动恢复，无需重启服务或修改配置。
* 🛡️ 高可用性：有效解决动态公网 IP（如家庭宽带变更）导致的连接中断问题。
* ✨ 优雅设计：逻辑封装良好，避免了对原生客户端的粗暴操作干扰，替代了不稳定的第三方脚本方案。
  
---

# [WireGuard](https://www.wireguard.com/) for Windows

This is a fully-featured WireGuard client for Windows that uses [WireGuardNT](https://git.zx2c4.com/wireguard-nt/about/). It is the only official and recommended way of using WireGuard on Windows.

## Download &amp; Install

If you've come here looking to simply run WireGuard for Windows, [the main download page has links](https://www.wireguard.com/install/). There you will find two things:

- [The WireGuard Installer](https://download.wireguard.com/windows-client/wireguard-installer.exe) &ndash; This selects the most recent version for your architecture, downloads it, checks signatures and hashes, and installs it.
- [Standalone MSIs](https://download.wireguard.com/windows-client/) &ndash; These are for system admins who wish to deploy the MSIs directly. For most end users, the ordinary installer takes care of downloading these automatically.

## Documentation

In addition to this [`README.md`](README.md), the following documents are also available:

- [`adminregistry.md`](docs/adminregistry.md) &ndash; A list of registry keys settable by the system administrator for changing the behavior of the application.
- [`attacksurface.md`](docs/attacksurface.md) &ndash; A discussion of the various components from a security perspective, so that future auditors of this code have a head start in assessing its security design.
- [`buildrun.md`](docs/buildrun.md) &ndash; Instructions on building, localizing, running, and developing for this repository.
- [`enterprise.md`](docs/enterprise.md) &ndash; A summary of various features and tips for making the application usable in enterprise settings.
- [`netquirk.md`](docs/netquirk.md) &ndash; A description of various networking quirks and "kill-switch" semantics.

## License

This repository is MIT-licensed.

```text
Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
