# listlanhost

`listlanhost`（简称 `lslh`）是一个使用 Rust 编写的局域网主机发现工具。它会自动读取当前默认网卡和 IPv4 子网，并发探测网段内的主机，最后以简洁表格输出在线设备。

当前版本：`0.2.0`

## 功能

- 自动识别默认网络接口和 IPv4 子网。
- 使用 Tokio 异步并发扫描，默认并发数为 300。
- TCP 端口探测：`21`、`22`、`80`、`135`、`445`、`3389`、`8080`、`25565`、`25566`、`60000`。
- UDP NetBIOS 探测：`137`。
- 同一主机可聚合显示多个命中的探测方式。
- 扫描结果按 IP 地址排序，便于快速查看。
- 输出尽量保持紧凑，适合在终端中直接使用。

## 下载

每次推送到 `main` 后，GitHub Actions 会自动构建二进制文件，并发布到新的 Release 资产中。Release tag 会自动生成随机值，不需要手动创建或推送 tag。

下载地址：

https://github.com/ra1nyxin/listlanhost/releases

常见资产命名类似：

- `listlanhost-0.2.0-windows-x86_64.exe`
- `listlanhost-0.2.0-linux-x86_64`
- `listlanhost-0.2.0-macos-x86_64`

## 从源码构建

需要本机已安装 Rust 工具链。

```bash
git clone https://github.com/ra1nyxin/listlanhost.git
cd listlanhost
cargo build --release
```

Windows 下生成：

```text
target\release\listlanhost.exe
```

Linux/macOS 下生成：

```text
target/release/listlanhost
```

如果想以 `lslh` 命令使用，可以把构建出的可执行文件复制到 PATH 中的目录，并重命名为 `lslh` 或 `lslh.exe`。

## 使用

直接运行：

```bash
listlanhost
```

如果你把程序重命名为 `lslh`：

```bash
lslh
```

示例输出：

```text
SCANNING 254 HOSTS (TIMEOUT 3s, CONCURRENCY 300)

SCAN RESULTS:
 IP ADDRESS      STATUS   METHODS
 192.168.1.1     ONLINE   TCP:80, TCP:445
 192.168.1.23    ONLINE   UDP:137
 192.168.1.105   ONLINE   TCP:25565
```

## 注意

- 这个工具会对当前局域网网段发起 TCP/UDP 探测，请只在你有权限的网络环境中使用。
- Windows 防火墙、路由器策略、设备休眠状态都可能影响扫描结果。
- UDP 探测不是强保证；没有 UDP 响应不代表主机一定离线。
- 当前版本不需要安装 Npcap，也不依赖 C 运行库。

## License

MIT
