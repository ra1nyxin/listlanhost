use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::Ipv4Network;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tabled::{settings::Style, Table, Tabled};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

<<<<<<< HEAD
#[derive(Tabled, Clone)]
=======
#[derive(Tabled)]
>>>>>>> ecc43631aee67319888d683a59389dc4bf3096b5
struct HostInfo {
    #[tabled(rename = "IP ADDRESS")]
    ip: String,
    #[tabled(rename = "STATUS")]
    status: String,
<<<<<<< HEAD
    #[tabled(rename = "METHODS")]
    method: String,
    #[tabled(display_with = "hidden")]
    u32_ip: u32, // 用于排序
}
fn hidden(_: &u32) -> String { "".to_string() }

#[tokio::main]
async fn main() {
    let interface = default_net::get_default_interface().expect("INTERFACE ERROR");
    let ipv4 = interface.ipv4.first().expect("IPV4 ERROR");
    let network = Ipv4Network::new(ipv4.addr, ipv4.prefix_len).unwrap();
    let hosts: Vec<Ipv4Addr> = network.iter().collect();

    println!("SCANNING {} HOSTS (TIMEOUT 3s, CONCURRENCY 300)", hosts.len());
    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] {bar:30.white/black} {pos}/{len}").unwrap());

    let semaphore = Arc::new(Semaphore::new(300));
=======
    #[tabled(rename = "METHOD")]
    method: String,
}

#[tokio::main]
async fn main() {
    let interface = default_net::get_default_interface().expect("FAILED TO GET INTERFACE");
    let ipv4 = interface.ipv4.first().expect("NO IPV4 FOUND");
    
    let network = Ipv4Network::new(ipv4.addr, ipv4.prefix_len).unwrap();
    let hosts: Vec<Ipv4Addr> = network.iter().collect();
    
    println!("SCANNING RANGE: {}/{}", ipv4.addr, ipv4.prefix_len);
    
    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:30.white/black} {pos}/{len}")
        .unwrap());

    let semaphore = Arc::new(Semaphore::new(150)); // 提高并发度至 150
>>>>>>> ecc43631aee67319888d683a59389dc4bf3096b5
    let mut tasks = Vec::new();

    for target_ip in hosts {
        let sem = Arc::clone(&semaphore);
        let pb_clone = pb.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let res = check_host(target_ip).await;
            pb_clone.inc(1);
            res
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
<<<<<<< HEAD
        if let Ok(Some(info)) = task.await { results.push(info); }
    }

    pb.finish_and_clear();

    if !results.is_empty() {
        results.sort_by_key(|h| h.u32_ip); // 严格按 IP 排序
        let mut table = Table::new(results);
        table.with(Style::blank());
        println!("\n{}\n{}", "SCAN RESULTS:".bold(), table);
=======
        if let Ok(Some(info)) = task.await {
            results.push(info);
        }
    }

    pb.finish_and_clear(); // 清除进度条，保持输出干净

    if !results.is_empty() {
        let mut table = Table::new(results);
        // 使用 Style::blank() 移除所有边框线
        table.with(Style::blank()); 
        println!("\n{}", "SCAN RESULTS:".bold());
        println!("{}", table);
    } else {
        println!("NO LIVE HOSTS DETECTED.");
>>>>>>> ecc43631aee67319888d683a59389dc4bf3096b5
    }
}

async fn check_host(ip: Ipv4Addr) -> Option<HostInfo> {
<<<<<<< HEAD
    let t_out = Duration::from_secs(3);
    let mut open_methods = Vec::new();
    let ports = [21, 22, 80, 135, 445, 3389, 8080, 25565, 25566, 60000];

    // TCP Check
    for port in ports {
        if timeout(t_out, TcpStream::connect(&SocketAddr::new(IpAddr::V4(ip), port))).await.is_ok() {
            open_methods.push(format!("TCP:{}", port));
        }
    }

    // UDP NetBIOS Check
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
        let _ = s.connect(SocketAddr::new(IpAddr::V4(ip), 137)).await;
        let query = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01];
        if s.send(&query).await.is_ok() {
            let mut buf = [0u8; 64];
            if timeout(t_out, s.recv(&mut buf)).await.is_ok() { open_methods.push("UDP:137".to_string()); }
        }
    }

    if open_methods.is_empty() { return None; }

    Some(HostInfo {
        ip: ip.to_string().white().to_string(),
        status: "ONLINE".green().bold().to_string(),
        method: open_methods.join(", ").dimmed().to_string(),
        u32_ip: u32::from(ip),
    })
}
=======
    // 缩短超时时间提高扫描效率
    let timeout_dur = Duration::from_millis(450);

    // 扩展后的端口列表
    let ports = [445, 135, 3389, 80, 22, 21, 25565, 25566];

    // TCP 扫描
    for port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        if timeout(timeout_dur, TcpStream::connect(&addr)).await.is_ok() {
            return Some(HostInfo {
                ip: ip.to_string().white().to_string(),
                status: "ONLINE".green().bold().to_string(),
                method: format!("TCP:{}", port).dimmed().to_string(),
            });
        }
    }

    // UDP NetBIOS 扫描 (保持作为兜底)
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
        if socket.connect(SocketAddr::new(IpAddr::V4(ip), 137)).await.is_ok() {
            let query = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01];
            let _ = socket.send(&query).await;
            let mut buf = [0u8; 64];
            if timeout(timeout_dur, socket.recv(&mut buf)).await.is_ok() {
                return Some(HostInfo {
                    ip: ip.to_string().white().to_string(),
                    status: "ONLINE".green().bold().to_string(),
                    method: "UDP:137".dimmed().to_string(),
                });
            }
        }
    }

    None
}
>>>>>>> ecc43631aee67319888d683a59389dc4bf3096b5
