# listlanhost

`listlanhost` (`lslh`) is a lightweight LAN device discovery tool written in Rust.

`listlanhost`（简称 `lslh`）是一个使用 Rust 编写的轻量级局域网设备发现工具，适合弱电施工、机房巡检、家庭/办公室网络排查、临时接入设备摸排等场景。

Current version / 当前版本：`0.2.2`

## What It Does / 它能做什么

The tool automatically reads the default network interface, calculates the local IPv4 subnet, scans active hosts concurrently, and prints a bilingual summary and result table.

它会自动读取默认网卡和本机 IPv4 子网，并发扫描网段内的在线主机，最后输出中英双语汇总和结果表。

The output includes device groups, service hints, web entry URLs, HTTP title/server details, and RTSP verification when available.

输出会给出设备分组、服务线索、后台入口 URL、HTTP 标题/Server 信息，以及可用时的 RTSP 验证结果，方便现场人员快速判断设备类型。

## Field-Oriented Improvements / 面向现场的改进

- Summary / 汇总统计：在线主机数、疑似摄像头/NVR、路由器/后台、Windows/NAS、打印机、IoT/UPnP、可打开后台入口数量。
- Grouped result order / 分组排序：优先显示 Camera/NVR、Router/Admin、Windows/NAS、Printer、IoT/UPnP 等设备线索。
- Web entry URLs / 后台入口：对常见后台端口自动生成 `http://` 或 `https://` URL，方便复制到浏览器。
- Combined inference / 组合判断：根据多个端口组合推断“更像路由器”“更像摄像头/NVR”“更像 Windows/NAS”等。
- HTTP title/server probe / HTTP 标题与 Server 探测：对明文 HTTP 后台发起轻量 `GET /`，读取 `<title>` 和 `Server`。
- RTSP verification / RTSP 验证：对 `554` 和 `8554` 发送 `OPTIONS * RTSP/1.0`，确认是否真像 RTSP 服务。
- No pcap dependency / 无 pcap 依赖：不需要 Npcap、WinPcap 或抓包驱动。

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

- `listlanhost-0.2.2-windows-x86_64.exe`
- `listlanhost-0.2.2-linux-x86_64`

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
SCANNING / 正在扫描 254 HOSTS / 主机 (LAN DEVICE DISCOVERY / 局域网设备发现, TCP 850ms, UDP 1200ms, APP 1200ms, CONCURRENCY / 并发 300)

SUMMARY / 汇总:
  Online hosts / 在线主机: 3
  Camera/NVR / 摄像头或录像机: 1
  Router/Admin / 路由器或后台: 1
  Windows/NAS / Windows或NAS: 1
  Printer / 打印机: 0
  IoT/UPnP / 智能设备: 0
  Web URLs / 可打开后台入口: 2
  HTTP/RTSP details / HTTP或RTSP详情: 2

SCAN RESULTS / 扫描结果:
IP ADDRESS / IP地址   STATUS / 状态   GROUP / 分组     HINTS / 设备线索                          SERVICES / 服务                                  URLS / 后台入口             DETAILS / 详情
192.168.1.32          ONLINE/在线     Camera/NVR      Camera/NVR 摄像头/录像机                   TCP:554(RTSP 视频流), TCP:8000(HTTP/SDK 摄像头)   http://192.168.1.32:8000/  RTSP:554 verified/已确认
192.168.1.1           ONLINE/在线     Router/Admin    Web/Admin 网页后台, DHCP/Router DHCP/路由器  TCP:80(HTTP 后台), UDP:67(DHCP 地址分配)          http://192.168.1.1/        HTTP:80 Title/标题:Router
192.168.1.50          ONLINE/在线     Windows/NAS     Windows/NAS 共享/NAS                       TCP:445(SMB 共享)                              -                            -
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
- HTTP title probing only supports plain HTTP. HTTPS URLs are still listed, but title extraction is not attempted without TLS dependencies.
- HTTP 标题探测只支持明文 HTTP。HTTPS 后台入口仍会列出，但在不引入 TLS 依赖的情况下不会尝试读取标题。
- Some routers, cameras, NVRs, printers, or firewalls may block probes.
- 部分路由器、摄像头、录像机、打印机或防火墙可能会拦截探测。
- A matched port is only a hint, not a final device fingerprint.
- 端口命中只是设备线索，不等于最终设备指纹。
- No Npcap, WinPcap, or packet capture driver is required.
- 不需要安装 Npcap、WinPcap 或抓包驱动。

## License / 许可证

MIT
