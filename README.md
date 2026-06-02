# listlanhost

`listlanhost` (`lslh`) is a lightweight LAN device discovery tool written in Rust.

`listlanhost`（简称 `lslh`）是一个使用 Rust 编写的轻量级局域网设备发现工具，适合弱电施工、机房巡检、家庭/办公室网络排查、临时接入设备摸排等场景。

Current version / 当前版本：`0.2.4`

## What It Does / 它能做什么

The tool automatically reads the default network interface, calculates the local IPv4 subnet, scans active hosts concurrently, and prints a bilingual field-friendly result.

它会自动读取默认网卡和本机 IPv4 子网，并发扫描网段内的在线主机，然后输出中英双语、适合现场查看的结果。

The output includes summary counters, grouped host cards, device hints, web entry URLs, HTTP status/title/server details, RTSP status/auth details, vendor fingerprints, default gateway marking, and automatic report files.

输出包含汇总统计、按设备类型分组的主机卡片、设备线索、后台入口 URL、HTTP 状态码/标题/Server、RTSP 状态/认证详情、厂商指纹、默认网关标记，并自动生成报告文件。

## Field-Oriented Improvements / 面向现场的改进

- Summary / 汇总统计：在线主机数、默认网关、疑似摄像头/NVR、路由器/后台、普通后台页面、Windows/NAS、打印机、IoT/UPnP、后台 URL、HTTP/RTSP 详情、指纹线索。
- Grouped card layout / 分组卡片布局：不再用一张很宽的表格，而是按 Camera/NVR、Router/Admin、Web/Admin、Windows/NAS 等分组输出，终端更容易看。
- Report files / 自动报告：每次扫描后自动在 `reports/` 目录生成 `txt`、`csv`、`json` 三份报告，文件名使用 UTC 日期时间，方便留档、发客户或导入表格。
- Web entry URLs / 后台入口：对常见后台端口自动生成 `http://` 或 `https://` URL，方便复制到浏览器。
- Combined inference / 组合判断：根据多个端口组合推断“更像路由器”“更像摄像头/NVR”“更像 Windows/NAS”“更像打印机”等。
- HTTP status/title/server probe / HTTP 状态、标题与 Server 探测：对明文 HTTP 后台发起更完整的轻量 `GET /`，读取最多 32KB 响应，提取状态码、`<title>` 和 `Server`；没有标题或 Server 时会明确显示 `no title/server 无标题/Server`。
- RTSP status/auth probe / RTSP 状态与认证探测：对 `554` 和 `8554` 发送 `OPTIONS * RTSP/1.0`，读取状态码、`Server` 和认证提示。
- Default gateway marking / 默认网关标记：如果系统能读取默认网关，会单独标记 `DEFAULT GATEWAY / 默认网关`。
- Vendor/device fingerprinting / 厂商与设备指纹：基于标题、Server、RTSP 响应等识别 Hikvision、Dahua、TP-LINK、OpenWrt、Synology、QNAP、nginx、IIS 等线索。
- Fewer false positives / 减少误报：单独命中普通 HTTP 后台不会直接归类成路由器；需要默认网关、DHCP、DNS+后台等组合线索才更偏 Router/Admin。
- No pcap dependency / 无 pcap 依赖：不需要 Npcap、WinPcap 或抓包驱动。

## Detection Coverage / 探测覆盖

`listlanhost` does not try to log in to any device. It only checks whether common service ports respond and reads lightweight banners when possible.

`listlanhost` 不会尝试登录任何设备，只做常见服务端口探测，并在可行时读取轻量级 banner/标题信息。

### Network Infrastructure / 网络基础设施

- Router/admin panels / 路由器与后台页面：`80`, `443`, `8080`, `8443`, `8888`, `9000`, `9090`
- DNS / DNS 服务：TCP/UDP `53`
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

- `listlanhost-0.2.4-windows-x86_64.exe`
- `listlanhost-0.2.4-linux-x86_64`

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
SCANNING / 正在扫描 254 HOSTS / 主机 (192.168.1.20 / 24, TCP 850ms, UDP 1200ms, APP 1200ms, CONCURRENCY / 并发 300)
DEFAULT GATEWAY / 默认网关: 192.168.1.1

SUMMARY / 汇总:
  Online hosts / 在线主机: 3
  Default gateway / 默认网关: 1
  Camera/NVR / 摄像头或录像机: 1
  Router/Admin / 路由器或后台: 1
  Web/Admin only / 普通后台页面: 0
  Windows/NAS / Windows或NAS: 1
  Printer / 打印机: 0
  IoT/UPnP / 智能设备: 0
  Web URLs / 可打开后台入口: 2
  HTTP details / HTTP详情: 1
  RTSP details / RTSP详情: 1
  Fingerprints / 指纹线索: 2

SCAN RESULTS / 扫描结果:

[Camera/NVR] 1 host(s)
192.168.1.32 ONLINE/在线
  Hints / 线索: Camera/NVR 摄像头/录像机 | Likely Camera/NVR 摄像头或录像机可能
  Services / 服务: TCP:554(RTSP 视频流) | TCP:8000(HTTP/SDK 摄像头)
  URLs / 后台入口: http://192.168.1.32:8000/
  Fingerprints / 指纹: Hikvision 海康威视
  RTSP / 视频流详情: RTSP:554 RTSP 401; Server:Embedded RTSP; Auth required/需要认证

[Router/Admin] 1 host(s)
192.168.1.1 ONLINE/在线  DEFAULT GATEWAY / 默认网关
  Hints / 线索: Default Gateway 默认网关 | Likely Router 路由器可能
  Services / 服务: SYSTEM:default-gateway(默认网关) | TCP:80(HTTP 后台)
  URLs / 后台入口: http://192.168.1.1/
  HTTP / 网页详情: http://192.168.1.1/ HTTP 200; Title/标题:Router; Fingerprint/指纹:TP-LINK 路由器

REPORTS / 报告文件:
  reports/listlanhost-report-2026-06-03-010000Z.txt
  reports/listlanhost-report-2026-06-03-010000Z.csv
  reports/listlanhost-report-2026-06-03-010000Z.json
```

## Report Files / 报告文件

The reports are written to the `reports/` directory under the current working directory.

报告会写入当前工作目录下的 `reports/` 目录。

- `.txt`: human-readable field report / 适合直接查看的现场报告
- `.csv`: spreadsheet-friendly report / 适合导入 Excel 或表格工具
- `.json`: structured data for scripts / 适合脚本或后续自动化处理

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
- Vendor fingerprinting is a hint based on banners and titles, not a final identification.
- 厂商指纹只是根据 banner 和标题推断的线索，不是最终设备鉴定。
- Some routers, cameras, NVRs, printers, or firewalls may block probes.
- 部分路由器、摄像头、录像机、打印机或防火墙可能会拦截探测。
- A matched port is only a hint, not a final device fingerprint.
- 端口命中只是设备线索，不等于最终设备指纹。
- No Npcap, WinPcap, or packet capture driver is required.
- 不需要安装 Npcap、WinPcap 或抓包驱动。

## License / 许可证

MIT
