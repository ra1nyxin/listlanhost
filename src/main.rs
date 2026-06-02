use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::Ipv4Network;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tabled::{settings::Style, Table, Tabled};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const CONCURRENCY_LIMIT: usize = 300;
const TCP_TIMEOUT: Duration = Duration::from_millis(850);
const UDP_TIMEOUT: Duration = Duration::from_millis(1200);
const VERSION: &str = env!("CARGO_PKG_VERSION");

struct HostInfo {
    ip: Ipv4Addr,
    hints: Vec<String>,
    services: Vec<String>,
}

#[derive(Tabled)]
struct HostRow {
    #[tabled(rename = "IP ADDRESS / IP地址")]
    ip: String,
    #[tabled(rename = "STATUS / 状态")]
    status: String,
    #[tabled(rename = "HINTS / 设备线索")]
    hints: String,
    #[tabled(rename = "SERVICES / 服务")]
    services: String,
}

impl From<HostInfo> for HostRow {
    fn from(info: HostInfo) -> Self {
        Self {
            ip: info.ip.to_string().white().to_string(),
            status: "ONLINE/在线".green().bold().to_string(),
            hints: info.hints.join(", ").cyan().to_string(),
            services: info.services.join(", ").dimmed().to_string(),
        }
    }
}

struct TcpProbe {
    port: u16,
    label: &'static str,
    hint: &'static str,
}

struct UdpProbe {
    port: u16,
    label: &'static str,
    hint: &'static str,
    payload: &'static [u8],
}

const NETBIOS_QUERY: &[u8] = &[
    0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
];

const SSDP_M_SEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\r\n";

const WS_DISCOVERY_PROBE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<e:Header>
<w:MessageID>uuid:6c736c68-0000-0000-0000-000000000001</w:MessageID>
<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
</e:Header>
<e:Body><d:Probe /></e:Body>
</e:Envelope>"#;

const TCP_PROBES: &[TcpProbe] = &[
    TcpProbe { port: 21, label: "FTP 文件", hint: "File/Device 文件/设备" },
    TcpProbe { port: 22, label: "SSH 远程", hint: "Linux/Device Linux/设备" },
    TcpProbe { port: 23, label: "Telnet 旧远程", hint: "Legacy/Device 老旧设备" },
    TcpProbe { port: 53, label: "DNS 域名", hint: "Router/DNS 路由器/DNS" },
    TcpProbe { port: 80, label: "HTTP 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 81, label: "HTTP-Alt 摄像头后台", hint: "Camera/Admin 摄像头后台" },
    TcpProbe { port: 88, label: "HTTP-Alt 摄像头后台", hint: "Camera/Admin 摄像头后台" },
    TcpProbe { port: 135, label: "MSRPC Windows", hint: "Windows 主机" },
    TcpProbe { port: 139, label: "NetBIOS 共享", hint: "Windows/NAS 共享/NAS" },
    TcpProbe { port: 443, label: "HTTPS 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 445, label: "SMB 共享", hint: "Windows/NAS 共享/NAS" },
    TcpProbe { port: 554, label: "RTSP 视频流", hint: "Camera/NVR 摄像头/录像机" },
    TcpProbe { port: 631, label: "IPP 打印", hint: "Printer 打印机" },
    TcpProbe { port: 1900, label: "SSDP 发现", hint: "UPnP/IoT 智能设备" },
    TcpProbe { port: 2869, label: "UPnP 发现", hint: "UPnP/IoT 智能设备" },
    TcpProbe { port: 3389, label: "RDP 远程桌面", hint: "Windows 主机" },
    TcpProbe { port: 5000, label: "HTTP-Alt NAS后台", hint: "NAS/Admin NAS后台" },
    TcpProbe { port: 5001, label: "HTTPS-Alt NAS后台", hint: "NAS/Admin NAS后台" },
    TcpProbe { port: 5357, label: "WSDAPI 设备发现", hint: "Printer/Windows 打印机/Windows" },
    TcpProbe { port: 8000, label: "HTTP/SDK 摄像头", hint: "Camera/NVR 摄像头/录像机" },
    TcpProbe { port: 8008, label: "HTTP-Alt 设备后台", hint: "IoT/Admin 智能设备后台" },
    TcpProbe { port: 8080, label: "HTTP-Alt 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 8081, label: "HTTP-Alt 摄像头后台", hint: "Camera/Admin 摄像头后台" },
    TcpProbe { port: 8443, label: "HTTPS-Alt 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 8554, label: "RTSP-Alt 视频流", hint: "Camera/NVR 摄像头/录像机" },
    TcpProbe { port: 8888, label: "HTTP-Alt 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 8899, label: "ONVIF-Alt 摄像头", hint: "Camera/NVR 摄像头/录像机" },
    TcpProbe { port: 9000, label: "HTTP-Alt 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 9090, label: "HTTP-Alt 后台", hint: "Web/Admin 网页后台" },
    TcpProbe { port: 37777, label: "DVR 录像机", hint: "Camera/NVR 摄像头/录像机" },
    TcpProbe { port: 34567, label: "DVR 录像机", hint: "Camera/NVR 摄像头/录像机" },
    TcpProbe { port: 60000, label: "Device 设备后台", hint: "Device/Admin 设备后台" },
    TcpProbe { port: 25565, label: "Minecraft 游戏", hint: "Game Server 游戏服务器" },
    TcpProbe { port: 25566, label: "Minecraft-Alt 游戏", hint: "Game Server 游戏服务器" },
];

const UDP_PROBES: &[UdpProbe] = &[
    UdpProbe { port: 67, label: "DHCP 地址分配", hint: "DHCP/Router DHCP/路由器", payload: &[] },
    UdpProbe { port: 137, label: "NetBIOS 主机名", hint: "NetBIOS/Windows 主机名/Windows", payload: NETBIOS_QUERY },
    UdpProbe { port: 1900, label: "SSDP 发现", hint: "UPnP/IoT 智能设备", payload: SSDP_M_SEARCH },
    UdpProbe { port: 3702, label: "WS-Discovery/ONVIF 摄像头", hint: "ONVIF/Camera 摄像头", payload: WS_DISCOVERY_PROBE },
];


#[tokio::main]
async fn main() {
    if handle_cli_flag() {
        return;
    }

    let interface = default_net::get_default_interface().expect("INTERFACE ERROR");
    let ipv4 = interface.ipv4.first().expect("IPV4 ERROR");
    let network = Ipv4Network::new(ipv4.addr, ipv4.prefix_len).expect("NETWORK ERROR");
    let hosts: Vec<Ipv4Addr> = network
        .iter()
        .filter(|ip| *ip != network.network() && *ip != network.broadcast())
        .collect();

    println!(
        "SCANNING / 正在扫描 {} HOSTS / 主机 (LAN DEVICE DISCOVERY / 局域网设备发现, TCP {}ms, UDP {}ms, CONCURRENCY / 并发 {})",
        hosts.len(),
        TCP_TIMEOUT.as_millis(),
        UDP_TIMEOUT.as_millis(),
        CONCURRENCY_LIMIT
    );

    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:30.white/black} {pos}/{len}")
            .unwrap(),
    );

    let semaphore = Arc::new(Semaphore::new(CONCURRENCY_LIMIT));
    let mut tasks = Vec::new();

    for target_ip in hosts {
        let sem = Arc::clone(&semaphore);
        let pb_clone = pb.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let result = check_host(target_ip).await;
            pb_clone.inc(1);
            result
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(Some(info)) = task.await {
            results.push(info);
        }
    }

    pb.finish_and_clear();

    if results.is_empty() {
        println!("NO LIVE HOSTS DETECTED / 未发现在线主机。");
        return;
    }

    results.sort_by_key(|host| u32::from(host.ip));
    let rows: Vec<HostRow> = results.into_iter().map(HostRow::from).collect();

    let mut table = Table::new(rows);
    table.with(Style::blank());
    println!("\n{}\n{}", "SCAN RESULTS / 扫描结果:".bold(), table);
}

fn handle_cli_flag() -> bool {
    let Some(arg) = env::args().nth(1) else {
        return false;
    };

    match arg.as_str() {
        "-h" | "--help" => {
            print_help();
            true
        }
        "-V" | "--version" => {
            println!("listlanhost {VERSION}");
            true
        }
        _ => false,
    }
}

fn print_help() {
    println!("listlanhost {VERSION}");
    println!();
    println!("Usage / 用法:");
    println!("  listlanhost");
    println!("  lslh");
    println!();
    println!("Options / 选项:");
    println!("  -h, --help       Show help / 显示帮助");
    println!("  -V, --version    Show version / 显示版本");
    println!();
    println!("Purpose / 用途:");
    println!("  Fast LAN device discovery for field work.");
    println!("  面向弱电施工、机房巡检、办公室/家庭网络排查的局域网设备发现。");
    println!();
    println!("Hints / 线索:");
    println!("  Router/Admin, DHCP, Camera/NVR, RTSP, ONVIF, NAS, Printer, Windows, IoT.");
    println!("  路由器/后台、DHCP、摄像头/录像机、RTSP、ONVIF、NAS、打印机、Windows、智能设备。");
}

async fn check_host(ip: Ipv4Addr) -> Option<HostInfo> {
    let mut hints = Vec::new();
    let mut services = Vec::new();

    for probe in TCP_PROBES {
        let addr = SocketAddr::new(IpAddr::V4(ip), probe.port);

        if matches!(
            timeout(TCP_TIMEOUT, TcpStream::connect(addr)).await,
            Ok(Ok(_))
        ) {
            push_unique(&mut hints, probe.hint.to_string());
            services.push(format!("TCP:{}({})", probe.port, probe.label));
        }
    }

    for probe in UDP_PROBES {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            let addr = SocketAddr::new(IpAddr::V4(ip), probe.port);

            let payload = if probe.port == 67 {
                dhcp_inform_payload()
            } else {
                probe.payload.to_vec()
            };

            if socket.connect(addr).await.is_err() || socket.send(&payload).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 64];

            if matches!(
                timeout(UDP_TIMEOUT, socket.recv(&mut buf)).await,
                Ok(Ok(_))
            ) {
                push_unique(&mut hints, probe.hint.to_string());
                services.push(format!("UDP:{}({})", probe.port, probe.label));
            }
        }
    }

    if services.is_empty() {
        return None;
    }

    Some(HostInfo {
        ip,
        hints,
        services,
    })
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn dhcp_inform_payload() -> Vec<u8> {
    let mut packet = vec![0u8; 240];

    packet[0] = 0x01; // BOOTREQUEST
    packet[1] = 0x01; // Ethernet
    packet[2] = 0x06; // MAC length
    packet[4..8].copy_from_slice(b"LSLH");
    packet[10] = 0x80; // Broadcast flag
    packet[28..34].copy_from_slice(&[0x02, 0x00, 0x4c, 0x53, 0x4c, 0x48]);
    packet[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

    packet.extend_from_slice(&[
        0x35, 0x01, 0x08, // DHCP Message Type: INFORM
        0x37, 0x03, 0x01, 0x03, 0x06, // Parameter request: subnet, router, DNS
        0xff,
    ]);

    packet
}
