# listlanhost

`listlanhost` (`lslh`) is a lightweight LAN device discovery tool written in Rust.

`listlanhost`（简称 `lslh`）是一个使用 Rust 编写的轻量级局域网设备发现工具，适合弱电施工、机房巡检、家庭/办公室网络排查、临时接入设备摸排等场景。

Current version / 当前版本：`0.2.1`

## What It Does / 它能做什么

The tool automatically reads the default network interface, calculates the local IPv4 subnet, scans active hosts concurrently, and prints a compact bilingual result table.

它会自动读取默认网卡和本机 IPv4 子网，并发扫描网段内的在线主机，最后输出中英双语表格。输出会尽量给出“设备线索”，方便现场人员快速判断设备类型。

## Detection Coverage / 探测覆盖

`listlanhost` does not try to log in to any device. It only checks whether common service ports respond.

`listlanhost` 不会尝试登录任何设备，只做常见服务端口探测。

### Network Infrastructure / 网络基础设施

- Router/admin panels / 路由器与后台页面：`80`, `443`, `8080`, `8443`, `8888`, `9000`, `9090`
- DNS / DNS 服务：`53`
- DHCP hint / DHCP 线索：UDP `67`
- UPnP / IoT discovery / UPnP 与智能设备发现：TCP/UDP `1900`, TCP `2869`

### CCTV and Weak Current Devices / 摄像头与弱电设备

- RTSP video streams / RTSP 视频流：`554`, `8554`
- ONVIF / WS-Discovery / 摄像头发现：UDP `3702`, TCP `8899`
- Camera/NVR/DVR panels or SDK ports / 摄像头、录像机、平台 SDK 常见端口：`81`, `88`, `8000`, `8081`, `37777`, `34567`, `60000`

### Office and Server Devices / 办公与服务器设备

- Windows/NAS sharing / Windows 或 NAS 共享：`139`, `445`
- Windows remote desktop / Windows 远程桌面：`3389`
- Printer discovery / 打印机发现：`631`, `5357`
- SSH/Telnet/FTP / 远程维护与文件服务：`21`, `22`, `23`

### Other / 其他

- Minecraft server / Minecraft 服务器：`25565`, `25566`
- UDP NetBIOS hostname check / UDP NetBIOS 主机名探测：`137`

## Download / 下载

Every push to `main` triggers GitHub Actions. The workflow builds binaries in the cloud and publishes a new Release with a generated tag, so no manual tag push is needed.

每次推送到 `main` 后，GitHub Actions 会自动在云端构建二进制文件，并用自动生成的 tag 发布到新的 Release。不需要本地创建或推送 tag。

Release page / 下载页：

https://github.com/ra1nyxin/listlanhost/releases

Assets / 常见资产：

- `listlanhost-0.2.1-windows-x86_64.exe`
- `listlanhost-0.2.1-linux-x86_64`

## Usage / 使用

Run directly / 直接运行：

```bash
listlanhost
```

If renamed to `lslh` / 如果重命名为 `lslh`：

```bash
lslh
```

Help and version / 帮助与版本：

```bash
listlanhost --help
listlanhost --version
```

Example / 示例：

```text
SCANNING / 正在扫描 254 HOSTS / 主机 (LAN DEVICE DISCOVERY / 局域网设备发现, TCP 850ms, UDP 1200ms, CONCURRENCY / 并发 300)

SCAN RESULTS / 扫描结果:
 IP ADDRESS / IP地址   STATUS / 状态   HINTS / 设备线索                 SERVICES / 服务
 192.168.1.1           ONLINE/在线     Web/Admin 网页后台, DHCP/Router DHCP/路由器   TCP:80(HTTP 后台), UDP:67(DHCP 地址分配)
 192.168.1.32          ONLINE/在线     Camera/NVR 摄像头/录像机        TCP:554(RTSP 视频流), TCP:8000(HTTP/SDK 摄像头)
 192.168.1.50          ONLINE/在线     Windows/NAS 共享/NAS            TCP:445(SMB 共享)
```

## Build From Source / 从源码构建

Rust toolchain is required.

需要本机已安装 Rust 工具链。

```bash
git clone https://github.com/ra1nyxin/listlanhost.git
cd listlanhost
cargo build --release
```

Windows output / Windows 产物：

```text
target\release\listlanhost.exe
```

Linux output / Linux 产物：

```text
target/release/listlanhost
```

## Notes / 注意事项

- Use it only on networks you own or are authorized to inspect.
- 请只在自己拥有或已获授权的网络中使用。
- UDP detection is best-effort. No UDP response does not always mean the device is offline.
- UDP 探测不是强保证；没有 UDP 响应不代表设备一定离线。
- Some routers, cameras, NVRs, printers, or firewalls may block probes.
- 部分路由器、摄像头、录像机、打印机或防火墙可能会拦截探测。
- A matched port is only a hint, not a final device fingerprint.
- 端口命中只是设备线索，不等于最终设备指纹。
- No Npcap or packet capture driver is required.
- 不需要安装 Npcap 或抓包驱动。

## License / 许可证

MIT
