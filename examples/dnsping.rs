//! Tiny DNS client for battle-testing the engine from the command line.
//!
//! Usage: `cargo run --example dnsping -- <server:port> <domain>`

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use dns_tunnel::core::dns::message::{TYPE_A, collect_a_records, encode_query, parse_questions};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(server), Some(domain)) = (args.next(), args.next()) else {
        eprintln!("usage: dnsping <server:port> <domain>");
        std::process::exit(2);
    };

    let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind ephemeral socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("failed to set timeout");
    // Unconnected on purpose: a connected socket silently discards
    // datagrams from unexpected sources; recv_from lets us report them.
    let server: std::net::SocketAddr = server.parse().expect("invalid server address");

    let query = encode_query(0xBEEF, &domain, TYPE_A).expect("failed to encode query");
    let sent = Instant::now();
    socket
        .send_to(&query, server)
        .expect("failed to send query");

    let mut buf = [0u8; 4096];
    match socket.recv_from(&mut buf) {
        Ok((len, source)) => {
            println!("reply from {source} ({len} bytes)");
            let bytes = &buf[..len];
            match parse_questions(bytes) {
                Ok((header, questions, cursor)) => {
                    println!(
                        "response: id {:04x}, flags {:04x}, in {:?}",
                        header.id,
                        header.flags,
                        sent.elapsed()
                    );
                    for question in &questions {
                        println!("  question: {} (type {})", question.name, question.qtype);
                    }
                    match collect_a_records(bytes, &header, cursor) {
                        Ok(addresses) => {
                            for ip in &addresses {
                                println!("  A {:?}", ip);
                            }
                            if addresses.is_empty() {
                                println!("  (no A records)");
                            }
                        }
                        Err(e) => println!("  (could not walk answer section: {e})"),
                    }
                }
                Err(e) => println!("unparsable response: {e}"),
            }
        }
        Err(e) => println!("no response within 3s: {e}"),
    }
}
