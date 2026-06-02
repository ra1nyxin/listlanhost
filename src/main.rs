use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::Ipv4Network;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tabled::{settings::Style, Table, Tabled};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const CONCURRENCY_LIMIT: usize = 300;
const TCP_TIMEOUT: Duration = Duration::from_millis(850);
const UDP_TIMEOUT: Duration = Duration::from_millis(1200);
const APP_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct HostInfo {
    ip: Ipv4Addr,
    group: String,
    hints: Vec<String>,
    services: Vec<String>,
    urls: Vec<String>,
    details: Vec<String>,
}

#[derive(Tabled)]
struct HostRow {
    #[tabled(rename = "IP ADDRESS / IP地址")]
    ip: String,
    #[tabled(rename = "STATUS / 状态")]
    status: String,
    #[tabled(rename = "GROUP / 分组")]
    group: String,
    #[tabled(rename = "HINTS / 设备线索")]
    hints: String,
    #[tabled(rename = "SERVICES / 服务")]
    services: String,
    #[tabled(rename = "URLS / 后台入口")]
    urls: String,
    #[tabled(rename = "DETAILS / 详情")]
    details: String,
}

impl From<&HostInfo> for HostRow {
    fn from(info: &HostInfo) -> Self {
        Self {
            ip: info.ip.to_string().white().to_string(),
            status: "ONLINE/在线".green().bold().to_string(),
            group: info.group.clone().yellow().to_string(),
            hints: join_or_dash(&info.hints).cyan().to_string(),
            services: join_or_dash(&info.services).dimmed().to_string(),
            urls: join_or_dash(&info.urls),
            details: join_or_dash(&info.details),
        }
    }
}

#[derive(Clone, Copy)]
struct TcpProbe {
    port: u16,
    label: &'static str,
    hint: &'static str,
}

#[derive(Clone, Copy)]
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
        "SCANNING / 正在扫描 {} HOSTS / 主机 (LAN DEVICE DISCOVERY / 局域网设备发现, TCP {}ms, UDP {}ms, APP {}ms, CONCURRENCY / 并发 {})",
        hosts.len(),
        TCP_TIMEOUT.as_millis(),
        UDP_TIMEOUT.as_millis(),
        APP_PROBE_TIMEOUT.as_millis(),
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

    results.sort_by_key(|host| (group_priority(&host.group), u32::from(host.ip)));

    print_summary(&results);

    let rows: Vec<HostRow> = results.iter().map(HostRow::from).collect();
    let mut table = Table::new(rows);
    table.with(Style::blank());
    println!("\n{}\n{}", "SCAN RESULTS / 扫描结果:".bold(), table);
}

async fn check_host(ip: Ipv4Addr) -> Option<HostInfo> {
    let mut hints = Vec::new();
    let mut services = Vec::new();
    let mut tcp_open = Vec::new();
    let mut udp_open = Vec::new();

    for probe in TCP_PROBES {
        let addr = SocketAddr::new(IpAddr::V4(ip), probe.port);

        if matches!(timeout(TCP_TIMEOUT, TcpStream::connect(addr)).await, Ok(Ok(_))) {
            tcp_open.push(probe.port);
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

            let mut buf = [0u8; 512];
            if matches!(timeout(UDP_TIMEOUT, socket.recv(&mut buf)).await, Ok(Ok(_))) {
                udp_open.push(probe.port);
                push_unique(&mut hints, probe.hint.to_string());
                services.push(format!("UDP:{}({})", probe.port, probe.label));
            }
        }
    }

    if services.is_empty() {
        return None;
    }

    apply_combination_hints(&mut hints, &tcp_open, &udp_open);

    let urls = build_web_urls(ip, &tcp_open);
    let mut details = Vec::new();

    for port in tcp_open.iter().copied().filter(|port| is_plain_http_probe_port(*port)) {
        if let Some(info) = probe_http_info(ip, port).await {
            details.push(format!("HTTP:{port} {info}"));
        }
    }

    for port in tcp_open.iter().copied().filter(|port| is_rtsp_port(*port)) {
        if probe_rtsp(ip, port).await {
            details.push(format!("RTSP:{port} verified/已确认"));
            push_unique(&mut hints, "Camera/NVR 摄像头/录像机".to_string());
        }
    }

    let group = classify_group(&hints);

    Some(HostInfo {
        ip,
        group,
        hints,
        services,
        urls,
        details,
    })
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

fn print_summary(results: &[HostInfo]) {
    let camera = count_group(results, "Camera/NVR");
    let router = count_group(results, "Router/Admin");
    let nas_windows = count_group(results, "Windows/NAS");
    let printer = count_group(results, "Printer");
    let iot = count_group(results, "IoT/UPnP");
    let web_urls = results.iter().filter(|host| !host.urls.is_empty()).count();
    let app_details = results.iter().filter(|host| !host.details.is_empty()).count();

    println!();
    println!("{}", "SUMMARY / 汇总:".bold());
    println!("  Online hosts / 在线主机: {}", results.len());
    println!("  Camera/NVR / 摄像头或录像机: {camera}");
    println!("  Router/Admin / 路由器或后台: {router}");
    println!("  Windows/NAS / Windows或NAS: {nas_windows}");
    println!("  Printer / 打印机: {printer}");
    println!("  IoT/UPnP / 智能设备: {iot}");
    println!("  Web URLs / 可打开后台入口: {web_urls}");
    println!("  HTTP/RTSP details / HTTP或RTSP详情: {app_details}");
}

fn count_group(results: &[HostInfo], group: &str) -> usize {
    results.iter().filter(|host| host.group == group).count()
}

fn apply_combination_hints(hints: &mut Vec<String>, tcp_open: &[u16], udp_open: &[u16]) {
    if (has_any(tcp_open, &[80, 443, 8080, 8443]) && has_any(tcp_open, &[53]))
        || udp_open.contains(&67)
    {
        push_unique(hints, "Likely Router 路由器可能".to_string());
    }

    if has_any(tcp_open, &[554, 8554])
        && has_any(tcp_open, &[80, 81, 88, 8000, 8081, 8899, 37777, 34567])
    {
        push_unique(hints, "Likely Camera/NVR 摄像头或录像机可能".to_string());
    }

    if has_any(tcp_open, &[8000, 8899, 37777, 34567]) || udp_open.contains(&3702) {
        push_unique(hints, "ONVIF/DVR clue 摄像头协议线索".to_string());
    }

    if tcp_open.contains(&445) && has_any(tcp_open, &[139, 135]) {
        push_unique(hints, "Likely Windows/NAS Windows或NAS可能".to_string());
    }

    if tcp_open.contains(&631) || tcp_open.contains(&5357) {
        push_unique(hints, "Likely Printer 打印机可能".to_string());
    }

    if udp_open.contains(&1900) || tcp_open.contains(&2869) {
        push_unique(hints, "Likely IoT/UPnP 智能设备可能".to_string());
    }
}

fn classify_group(hints: &[String]) -> String {
    if contains_hint(hints, "Camera/NVR") || contains_hint(hints, "ONVIF") {
        "Camera/NVR".to_string()
    } else if contains_hint(hints, "Router")
        || contains_hint(hints, "DHCP")
        || contains_hint(hints, "Web/Admin")
    {
        "Router/Admin".to_string()
    } else if contains_hint(hints, "Windows/NAS") || contains_hint(hints, "Windows 主机") {
        "Windows/NAS".to_string()
    } else if contains_hint(hints, "Printer") {
        "Printer".to_string()
    } else if contains_hint(hints, "IoT") || contains_hint(hints, "UPnP") {
        "IoT/UPnP".to_string()
    } else if contains_hint(hints, "Game Server") {
        "Game Server".to_string()
    } else {
        "Other/其他".to_string()
    }
}

fn group_priority(group: &str) -> u8 {
    match group {
        "Camera/NVR" => 0,
        "Router/Admin" => 1,
        "Windows/NAS" => 2,
        "Printer" => 3,
        "IoT/UPnP" => 4,
        "Game Server" => 5,
        _ => 9,
    }
}

fn build_web_urls(ip: Ipv4Addr, tcp_open: &[u16]) -> Vec<String> {
    let mut urls = Vec::new();

    for port in tcp_open.iter().copied().filter(|port| is_web_port(*port)) {
        let scheme = if is_https_port(port) { "https" } else { "http" };
        let url = match (scheme, port) {
            ("http", 80) => format!("http://{ip}/"),
            ("https", 443) => format!("https://{ip}/"),
            _ => format!("{scheme}://{ip}:{port}/"),
        };
        push_unique(&mut urls, url);
    }

    urls
}

async fn probe_http_info(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = timeout(APP_PROBE_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: listlanhost/{VERSION}\r\n\r\n");
    timeout(APP_PROBE_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(APP_PROBE_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buf[..n]).to_string();
    extract_http_info(&response)
}

async fn probe_rtsp(ip: Ipv4Addr, port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let Ok(Ok(mut stream)) = timeout(APP_PROBE_TIMEOUT, TcpStream::connect(addr)).await else {
        return false;
    };

    let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    if !matches!(
        timeout(APP_PROBE_TIMEOUT, stream.write_all(request)).await,
        Ok(Ok(()))
    ) {
        return false;
    }

    let mut buf = [0u8; 512];
    let Ok(Ok(n)) = timeout(APP_PROBE_TIMEOUT, stream.read(&mut buf)).await else {
        return false;
    };

    String::from_utf8_lossy(&buf[..n]).contains("RTSP/")
}

fn extract_http_info(response: &str) -> Option<String> {
    let server = header_value(response, "server").map(|value| format!("Server:{value}"));
    let title = html_title(response).map(|value| format!("Title/标题:{value}"));

    match (title, server) {
        (Some(title), Some(server)) => Some(format!("{title}; {server}")),
        (Some(title), None) => Some(title),
        (None, Some(server)) => Some(server),
        (None, None) => None,
    }
}

fn header_value(response: &str, header: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(header) {
            Some(truncate(clean_text(value), 80))
        } else {
            None
        }
    })
}

fn html_title(response: &str) -> Option<String> {
    let lower = response.to_ascii_lowercase();
    let title_start = lower.find("<title")?;
    let title_open_end = lower[title_start..].find('>')? + title_start + 1;
    let title_close = lower[title_open_end..].find("</title>")? + title_open_end;
    let title = &response[title_open_end..title_close];
    let title = decode_basic_entities(&clean_text(title));

    if title.is_empty() {
        None
    } else {
        Some(truncate(title, 80))
    }
}

fn clean_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode_basic_entities(value: &str) -> String {
    value
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn truncate(value: String, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();

    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn is_web_port(port: u16) -> bool {
    matches!(
        port,
        80 | 81 | 88 | 443 | 5000 | 5001 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 9000 | 9090
    )
}

fn is_plain_http_probe_port(port: u16) -> bool {
    is_web_port(port) && !is_https_port(port)
}

fn is_https_port(port: u16) -> bool {
    matches!(port, 443 | 5001 | 8443)
}

fn is_rtsp_port(port: u16) -> bool {
    matches!(port, 554 | 8554)
}

fn has_any(values: &[u16], needles: &[u16]) -> bool {
    needles.iter().any(|needle| values.contains(needle))
}

fn contains_hint(hints: &[String], needle: &str) -> bool {
    hints.iter().any(|hint| hint.contains(needle))
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
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
