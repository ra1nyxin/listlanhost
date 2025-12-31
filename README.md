# listlanhost (lslh)

A high-concurrency LAN host discovery tool written in Rust.
一款使用 Rust 编写的高并发局域网主机发现工具。

## Description / 项目简介

listlanhost (lslh) is a lightweight CLI tool designed for rapid scanning of active devices in a local area network. It uses asynchronous I/O to perform TCP and UDP probing simultaneously, providing a compact and clean output without unnecessary decorations.

listlanhost (lslh) 一款轻量级的命令行工具，专为快速扫描局域网内的活动设备而设计。利用异步 I/O 同时进行 TCP 和 UDP 探测，提供简洁紧凑的输出。

## Features / 功能特性

* High performance asynchronous scanning powered by Tokio.
  基于 Tokio 实现的高性能异步扫描。
* Multi-protocol detection: TCP (21, 22, 80, 135, 445, 3389, 25565, 25566) and UDP (NetBIOS).
  多协议探测：支持 TCP 及 UDP (NetBIOS) 探测。
* Minimalist output format suitable for terminal integration.
  极简的输出格式，适合终端集成。
* Automatic network interface and subnet detection.
  自动识别网卡及子网掩码。
* No C-runtime dependencies (pure Rust implementation).
  无 C 语言运行库依赖（纯 Rust 实现）。

## Installation / 安装方式

### Binary Download / 下载二进制文件

You can download the pre-compiled executable for Windows directly:
您可以直接下载预编译的 Windows 可执行文件：

[Download listlanhost.exe v1.0.0](https://github.com/ra1nyxin/listlanhost/releases/download/1.0.0/listlanhost.exe)

### From Source / 从源码编译

```bash
git clone [https://github.com/ra1nyxin/listlanhost](https://github.com/ra1nyxin/listlanhost)
cd listlanhost
cargo build --release

```

To use it globally as `lslh`, move the executable to a directory in your PATH and rename it:
若想全局使用 `lslh` 命令，请将生成的程序移动至 PATH 目录并重命名：

```powershell
copy .\target\release\listlanhost.exe $HOME\.cargo\bin\lslh.exe

```

## Usage / 使用方法

Simply run the command in your terminal:
只需在终端中运行以下命令：

```cmd
lslh

```

### Example Output / 输出示例

```text
SCANNING RANGE: 192.168.1.105/24 [##############################] 254/254

SCAN RESULTS:
 IP ADDRESS      STATUS   METHOD 
 192.168.1.1     ONLINE   TCP:80 
 192.168.1.102   ONLINE   TCP:3389 
 192.168.1.105   ONLINE   UDP:137

```

## License / 许可协议

This project is licensed under the MIT License.
本项目采用 MIT 许可协议。

---

Copyright (c) 2025 ra1nyxin
qwq
