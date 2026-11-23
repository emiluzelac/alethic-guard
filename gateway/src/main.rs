use alethic_guard_gateway::receipt::verify_receipt;
use alethic_guardd::{
    GuardResult,
    auth::peer_uid,
    broker::Prepared,
    collector::{Collector, GuestRequest, public_ip},
    effect::Outcome,
    protocol::{configure, read_frame, write_frame},
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
    os::{fd::FromRawFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_REQUEST: u64 = 2048;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

fn rpc<T: DeserializeOwned>(path: &Path, request: Value) -> GuardResult<T> {
    let mut socket = UnixStream::connect(path)?;
    configure(&socket)?;
    if peer_uid(&socket)? != 0 {
        return Err("daemon has unexpected host credentials".into());
    }
    write_frame(&mut socket, &request)?;
    let response: Value = read_frame(&socket)?;
    if response["ok"] != true {
        return Err("daemon refused the effect".into());
    }
    Ok(serde_json::from_value(response["result"].clone())?)
}

fn tls_config(ca: Option<&Path>) -> GuardResult<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca {
        let mut file = BufReader::new(File::open(path)?);
        for cert in rustls_pemfile::certs(&mut file) {
            roots.add(cert?)?;
        }
        if roots.is_empty() {
            return Err("configured CA file contains no certificates".into());
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

fn collect(
    daemon: &Path,
    tls: Arc<ClientConfig>,
    prepared: &Prepared,
    payload: &[u8],
    effect_may_be_sent: &mut bool,
) -> GuardResult<()> {
    let target = Collector::parse_url(&prepared.action.target)?;
    if prepared.dial.port() != target.port || !public_ip(prepared.dial.ip()) {
        return Err("dial address outside the collector boundary".into());
    }
    let recheck = || -> GuardResult<()> {
        rpc::<Value>(
            daemon,
            json!({"command": "broker_check", "nonce": prepared.nonce}),
        )
        .map(|_| ())
    };
    recheck()?;
    let mut tcp = TcpStream::connect_timeout(&prepared.dial, IO_TIMEOUT)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    let name = ServerName::try_from(target.host.clone())?;
    let mut connection = ClientConnection::new(tls, name)?;
    let deadline = Instant::now() + IO_TIMEOUT;
    while connection.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("collector handshake timed out".into());
        }
        connection.complete_io(&mut tcp)?;
    }
    let mut transport = StreamOwned::new(connection, tcp);
    let host = if target.port == 443 {
        target.host
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nIdempotency-Key: {}\r\nConnection: close\r\n\r\n",
        target.path,
        payload.len(),
        prepared.action.idempotency_key,
    )
    .into_bytes();
    request.extend(payload);
    recheck()?;
    *effect_may_be_sent = true;
    transport.write_all(&request)?;
    transport.flush()?;
    verify_receipt(
        transport,
        prepared.action.idempotency_key,
        &prepared.action.payload_sha256,
    )
}

fn process_request(
    daemon: &Path,
    tls: Arc<ClientConfig>,
    incoming: GuestRequest,
) -> GuardResult<Outcome> {
    let body = incoming.payload()?;
    let digest = incoming.payload_digest()?;
    let prepared: Prepared = rpc(
        daemon,
        json!({"command": "broker_prepare", "request": incoming}),
    )?;
    if prepared.action.operation != incoming.operation
        || prepared.action.request_id != incoming.request_id
        || prepared.action.payload_sha256 != digest
        || prepared.action.data_labels != ["public"]
    {
        return Err("daemon returned a different action".into());
    }
    rpc::<Value>(
        daemon,
        json!({
            "command": "broker_redeem", "nonce": prepared.nonce, "action": prepared.action,
        }),
    )?;
    let mut sent = false;
    let outcome = match collect(daemon, tls, &prepared, body, &mut sent) {
        Ok(()) => Outcome::Succeeded,
        Err(error) => {
            eprintln!("collector transport: {error}");
            if sent {
                Outcome::OutcomeUnknown
            } else {
                Outcome::Failed
            }
        }
    };
    let recorded = rpc::<Value>(
        daemon,
        json!({"command": "broker_finish", "nonce": prepared.nonce, "outcome": outcome}),
    );
    Ok(if recorded.is_err() {
        Outcome::OutcomeUnknown
    } else {
        outcome
    })
}

fn parse_request(daemon: &Path, frame: &[u8]) -> GuardResult<GuestRequest> {
    let request = serde_json::from_slice::<GuestRequest>(frame);
    match request {
        Ok(request) if request.payload().is_ok() => Ok(request),
        denied => {
            let reason = if denied.is_ok() {
                "unapproved_fixture"
            } else {
                "invalid_schema"
            };
            let _ = rpc::<Value>(
                daemon,
                json!({"command": "broker_denial", "reason": reason}),
            );
            Err("invalid guest request".into())
        }
    }
}

fn run() -> GuardResult<()> {
    let mut args = std::env::args_os().skip(1);
    let daemon: PathBuf = args.next().ok_or("missing daemon socket")?.into();
    let ca = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("unexpected gateway arguments".into());
    }
    let tls = tls_config(ca.as_deref())?;
    // guardd passes the verified, already connected per-domain QEMU endpoint.
    let mut channel = unsafe { UnixStream::from_raw_fd(3) };
    channel.set_read_timeout(Some(IO_TIMEOUT))?;
    channel.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut incoming = BufReader::new(channel.try_clone()?);
    let mut last = None;
    loop {
        let mut frame = Vec::new();
        let result = incoming
            .by_ref()
            .take(MAX_REQUEST + 1)
            .read_until(b'\n', &mut frame);
        match result {
            Ok(0) => break,
            Ok(_) if frame.last() == Some(&b'\n') && frame.len() as u64 <= MAX_REQUEST => {}
            Err(error)
                if frame.is_empty()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
            {
                continue;
            }
            _ => return Err("invalid or incomplete guest request frame".into()),
        }
        let result = if last.is_some_and(|time: Instant| time.elapsed() < Duration::from_secs(1)) {
            Err("guest request rate exceeded".into())
        } else {
            last = Some(Instant::now());
            parse_request(&daemon, &frame)
                .and_then(|request| process_request(&daemon, tls.clone(), request))
        };
        let response = match result {
            Ok(outcome) => json!({"outcome": outcome}),
            Err(_) => json!({"outcome": "DENIED"}),
        };
        write_frame(&mut channel, &response)?;
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("alethic-guard-gateway: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
