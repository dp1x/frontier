// rustls_server is the msn-2026-0005 / exp-2026-0018 server cohort for the
// protocol-layer ML-KEM ek validation interop matrix.
//
// Per-variant protocol:
//
//   1. The Go harness spawns this binary with env vars:
//        RUSTLS_LOOPBACK_PORT=NNNNN          -- TCP port to bind
//        RUSTLS_LOOPBACK_MODE=<mode>         -- name of variant (echoed into JSON)
//        RUSTLS_LOOPBACK_VARIANT_NUM=<n>     -- monotonic variant index
//
//   2. We install the aws_lc_rs CryptoProvider, build a self-signed cert at
//      runtime via rcgen, configure rustls 0.23.43 ServerConfig for TLS 1.3
//      only with the default kx group ordering (which now includes
//      X25519MLKEM768 first, per the prefer-post-quantum feature).
//
//   3. We accept exactly one TCP connection, drive the handshake to
//      completion (or its failure) using process_new_packets + read_tls +
//      write_tls on the raw TCP stream, capture the resulting rustls::Error
//      and any AlertReceived variant, write a JSON status line on stdout,
//      and exit with status 0 (always -- the failure mode is recorded in
//      the RESULT JSON line).
//
// Stdout is the *single* IPC contract. Lines:
//   META|<key>=<value>            -- runtime metadata
//   RESULT|{"ok":bool,"variant":string,"error":string,"alert":string}
//   DONE
//
// stderr carries env_logger output (warn!/error!) for debugging; the Go
// harness forwards it to the report file but does not parse it.

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp_millis()
        .init();

    let port: u16 = match env::var("RUSTLS_LOOPBACK_PORT") {
        Ok(s) => match s.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("RUSTLS_LOOPBACK_PORT parse error: {e}");
                return ExitCode::from(2);
            }
        },
        Err(e) => {
            eprintln!("RUSTLS_LOOPBACK_PORT not set: {e}");
            return ExitCode::from(2);
        }
    };
    let mode = env::var("RUSTLS_LOOPBACK_MODE").unwrap_or_else(|_| "unknown".to_string());
    let variant_num: u32 = env::var("RUSTLS_LOOPBACK_VARIANT_NUM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Install aws-lc-rs as the process-default provider. This is what msn-
    // 2026-0005 cares about -- the BoringSSL-derived FIPS 203 ML-KEM
    // implementation.
    let _ = provider::default_provider().install_default();

    println!(
        "META|rustls_version={}|aws_lc_rs=installed|provider=aws_lc_rs|\
mode={mode}|variant_num={variant_num}|port={port}",
        env!("CARGO_PKG_VERSION")
    );

    // Build a self-signed cert for localhost.
    let CertifiedKey { cert, key_pair } = match generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cert generation failed: {e}");
            return ExitCode::from(2);
        }
    };
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let cfg = match ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ServerConfig::builder failed: {e}");
            return ExitCode::from(2);
        }
    };
    let server_cfg = Arc::new(cfg);

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return ExitCode::from(2);
        }
    };
    // Signal readiness on stdout. The harness dials the probe only after
    // seeing this line, so we don't race the listener binding.
    println!("READY");
    eprintln!("listening on 127.0.0.1:{port} for mode={mode}");

    // Accept exactly one connection.
    let (mut tcp, _peer) = match listener.accept() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("accept failed: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT)) {
        eprintln!("set_read_timeout: {e}");
    }
    if let Err(e) = tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT)) {
        eprintln!("set_write_timeout: {e}");
    }

    let mut server = match rustls::ServerConnection::new(server_cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ServerConnection::new failed: {e}");
            return ExitCode::from(2);
        }
    };

    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut last_err: Option<rustls::Error> = None;

    while Instant::now() < deadline && server.is_handshaking() {
        // Plumb TCP -> server.
        if server.wants_read() {
            let mut tmp = [0u8; 16 * 1024];
            match tcp.read(&mut tmp) {
                Ok(0) => break, // peer closed cleanly
                Ok(n) => {
                    let mut cursor = std::io::Cursor::new(&tmp[..n]);
                    if let Err(e) = server.read_tls(&mut cursor) {
                        last_err = Some(rustls::Error::General(format!("read_tls io: {e}")));
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // No data right now; keep looping so write_tls can drain.
                }
                Err(e) => {
                    last_err = Some(rustls::Error::General(format!("tcp io: {e}")));
                    break;
                }
            }
        }

        // Drive the TLS state machine.
        match server.process_new_packets() {
            Ok(_io) => {}
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }

        // Plumb server -> TCP.
        while server.wants_write() {
            let mut out = [0u8; 16 * 1024];
            match server.write_tls(&mut out.as_mut_slice()) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = tcp.write_all(&out[..n]) {
                        last_err = Some(rustls::Error::General(format!("tcp write_all: {e}")));
                        break;
                    }
                }
                Err(e) => {
                    last_err = Some(rustls::Error::General(format!("tcp io: {e}")));
                    break;
                }
            }
        }
    }

    // Drain any final write (e.g., fatal alert queued by an error).
    while server.wants_write() {
        let mut out = [0u8; 16 * 1024];
        match server.write_tls(&mut out.as_mut_slice()) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tcp.write_all(&out[..n]).is_err() {
                    break;
                }
            }
        }
    }

    let (ok, error_str, alert_str) = match last_err {
        Some(e) => (false, format!("{e}"), extract_alert(&e)),
        None if server.is_handshaking() => {
            (false, "handshake timed out".to_string(), String::new())
        }
        None => (true, String::new(), String::new()),
    };

    // Sanitize for the JSON line: strip control chars that would break the line.
    let safe_variant = sanitize_for_log(&mode);
    let safe_error = sanitize_for_log(&error_str);
    let safe_alert = sanitize_for_log(&alert_str);
    println!(
        "RESULT|{{\"ok\":{ok},\"variant\":\"{safe_variant}\",\"error\":\"{safe_error}\",\"alert\":\"{safe_alert}\"}}"
    );
    println!("DONE");

    let _ = tcp.shutdown(std::net::Shutdown::Both);
    ExitCode::SUCCESS
}

fn sanitize_for_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii() && !ch.is_control() {
            out.push(ch);
        } else if !ch.is_ascii() {
            // Permit non-control non-ASCII; fall through and replace.
            out.push('?');
        } else {
            out.push('?');
        }
    }
    out
}

fn extract_alert(err: &rustls::Error) -> String {
    use rustls::Error;
    match err {
        Error::AlertReceived(a) => format!("alert_received:{a:?}"),
        Error::PeerMisbehaved(m) => format!("peer_misbehaved:{m:?}"),
        Error::InvalidMessage(m) => format!("invalid_message:{m:?}"),
        Error::PeerIncompatible(m) => format!("peer_incompatible:{m:?}"),
        Error::General(g) => format!("general:{g}"),
        Error::DecryptError => "decrypt_error".to_string(),
        Error::EncryptError => "encrypt_error".to_string(),
        _ => format!("other:{err:?}"),
    }
}