use alethic_guardd::{
    GuardResult,
    auth::peer_uid,
    broker,
    collector::{BROKER_GROUP, Collector, CollectorConfig, GuestRequest},
    digest_file,
    effect::{Action, Outcome},
    evidence,
    lifecycle::{Enrolled, Lifecycle, Registry, Workload},
    protocol::{configure, read_frame, write_frame},
    vm::{Libvirt, create_overlay, validate_base_image},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
        },
    },
    path::{Path, PathBuf},
    thread,
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Create {
        profile: String,
        image: String,
        input: Option<String>,
    },
    Start {
        id: Uuid,
    },
    Status {
        id: Uuid,
    },
    Verify {
        id: Uuid,
    },
    Pause {
        id: Uuid,
    },
    Resume {
        id: Uuid,
    },
    Contain {
        id: Uuid,
    },
    Terminate {
        id: Uuid,
    },
    Release {
        id: Uuid,
    },
    BrokerPrepare {
        request: GuestRequest,
    },
    BrokerRedeem {
        nonce: Uuid,
        action: Action,
    },
    BrokerDenial {
        reason: BrokerDenial,
    },
    BrokerCheck {
        nonce: Uuid,
    },
    BrokerFinish {
        nonce: Uuid,
        outcome: Outcome,
    },
    EffectStatus {
        id: Uuid,
        request: Uuid,
    },
    ReconcileReceipt {
        id: Uuid,
        request: Uuid,
        key: Uuid,
        payload_sha256: String,
    },
    EvidencePage {
        id: Uuid,
        after: u64,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrokerDenial {
    InvalidSchema,
    UnapprovedFixture,
}

struct Config {
    data: PathBuf,
    policies: PathBuf,
    socket: PathBuf,
    collector: Option<CollectorConfig>,
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn secure_directory(dir: &Path) -> GuardResult<()> {
    if !dir.is_absolute() || fs::canonicalize(dir)? != dir {
        return Err("expected an absolute canonical directory".into());
    }
    for ancestor in dir.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(format!("expected a root-owned directory: {}", ancestor.display()).into());
        }
    }
    Ok(())
}

fn approved_file(dir: &Path, name: &str) -> GuardResult<PathBuf> {
    if !safe_name(name) {
        return Err("expected an approved filename, without a path".into());
    }
    secure_directory(dir)?;
    let path = dir.join(name);
    let meta = fs::symlink_metadata(&path)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o222 != 0 || meta.nlink() != 1 {
        return Err("approved artifacts must be immutable regular files owned by root".into());
    }
    Ok(path)
}

impl Config {
    fn policy(&self, profile: &str) -> GuardResult<(String, bool, bool)> {
        let path = approved_file(&self.policies, &format!("{profile}.json"))?;
        if fs::metadata(&path)?.len() > 65_536 {
            return Err("policy exceeds maximum size".into());
        }
        let plan: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let spec = &plan["spec"];
        if plan["api_version"] != "guard.alethic.dev/v1"
            || plan["kind"] != "WorkloadPolicy"
            || plan["metadata"]["name"] != profile
            || spec["isolation"] != "vm-isolated"
            || spec["enforce"] != true
            || spec["default_action"] != "deny"
            || spec["network"]["guest_direct_egress"] != "deny_all"
        {
            return Err("expected a compiled, fail-closed v1 policy".into());
        }
        let endpoints = spec["network"]["approved_broker_destinations"]
            .as_array()
            .ok_or("missing broker destinations")?;
        let broker = match spec["profile"].as_str() {
            Some("offline-strict") if endpoints.is_empty() => false,
            Some("allowlisted-api") if endpoints.len() == 1 => {
                let config = self
                    .collector
                    .as_ref()
                    .ok_or("mediated API is disabled on host")?;
                if endpoints[0] != config.target {
                    return Err("collector policy differs from host target".into());
                }
                Collector::parse_url(&config.target)?;
                true
            }
            _ => return Err("unsupported profile or invalid destination policy".into()),
        };
        let inputs = spec["filesystem"]["inputs"]
            .as_array()
            .ok_or("missing input volume policy")?;
        Ok((digest_file(&path)?, !inputs.is_empty(), broker))
    }

    fn validate_enrolled(&self, row: &Workload) -> GuardResult<()> {
        let a = &row.enrollment;
        let (actual_policy, has_input, broker) = self.policy(&a.profile)?;
        let images = self.data.join("images");
        let name = |path: &Path| -> GuardResult<String> {
            Ok(path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("invalid approved image name")?
                .to_owned())
        };
        if actual_policy != a.policy_digest
            || broker != a.broker
            || has_input != a.input.is_some()
            || approved_file(&images, &name(&a.image)?)? != a.image
            || digest_file(&a.image)? != a.image_digest
        {
            return Err("policy or base image changed since enrollment".into());
        }
        if let Some(input) = &a.input {
            if approved_file(&images, &name(input)?)? != *input
                || Some(digest_file(input)?) != a.input_digest
            {
                return Err("input image changed since enrollment".into());
            }
        }
        validate_base_image(&a.image)
    }

    fn overlay(&self, row: &Workload) -> GuardResult<PathBuf> {
        self.validate_enrolled(row)?;
        let path = self
            .data
            .join("run")
            .join(format!("{}-{}.qcow2", row.enrollment.id, row.generation));
        create_overlay(&path, &row.enrollment.image)?;
        Ok(path)
    }
}

fn broker_request(
    req: Request,
    registry: &mut Registry,
    config: &Config,
    uid: u32,
) -> GuardResult<Value> {
    let collector = config
        .collector
        .as_ref()
        .ok_or("gateway service disabled")?;
    let binding = registry.gateway_by_uid(uid)?;
    let item = registry.get(binding.id)?.ok_or("unmanaged gateway")?;
    let (digest, _, mediated) = config.policy(&item.enrollment.profile)?;
    if !mediated || digest != item.enrollment.policy_digest {
        return Err("the installed policy changed".into());
    }
    match req {
        Request::BrokerPrepare { request } => {
            Ok(json!(broker::prepare(registry, collector, uid, request)?))
        }
        Request::BrokerRedeem { nonce, action } => {
            let session = broker::controller_session(collector)?;
            registry.authenticate_controller_session(nonce, session)?;
            registry.redeem_grant(nonce, &action, uid, evidence::monotonic_ns()?)?;
            Ok(json!({}))
        }
        Request::BrokerDenial { reason } => {
            let result = match reason {
                BrokerDenial::InvalidSchema => "INVALID_SCHEMA",
                BrokerDenial::UnapprovedFixture => "UNAPPROVED_FIXTURE",
            };
            registry.record_gateway_denial(binding.id, result)?;
            Ok(json!({}))
        }
        Request::BrokerCheck { nonce } => {
            let session = broker::controller_session(collector)?;
            registry.authenticate_controller_session(nonce, session)?;
            registry.check_dispatch(nonce, uid, evidence::monotonic_ns()?)?;
            Ok(json!({}))
        }
        Request::BrokerFinish { nonce, outcome } => {
            registry.finish(nonce, uid, outcome)?;
            Ok(json!({}))
        }
        _ => Err("host root is required for operator operations".into()),
    }
}

fn attach_gateway(registry: &mut Registry, config: &Config, item: &Workload) -> GuardResult<()> {
    if !item.enrollment.broker {
        return Ok(());
    }
    let collector = config.collector.as_ref().ok_or("gateway disabled")?;
    match broker::start(registry, item, collector, &config.socket) {
        Ok(mut child) => {
            thread::spawn(move || {
                if let Err(error) = child.wait() {
                    eprintln!("gateway wait failed: {error}");
                }
            });
            Ok(())
        }
        Err(error) => {
            let _ = Lifecycle::new(registry, &Libvirt).contain(item.enrollment.id, true);
            Err(error)
        }
    }
}

fn handle(req: Request, registry: &mut Registry, config: &Config, uid: u32) -> GuardResult<Value> {
    if uid != 0 {
        return broker_request(req, registry, config, uid);
    }
    let vm = Libvirt;
    let mut lifecycle = Lifecycle::new(registry, &vm);
    let (result, event) = match req {
        Request::Create {
            profile,
            image,
            input,
        } => {
            let (policy_digest, has_input, broker) = config.policy(&profile)?;
            if has_input != input.is_some() {
                return Err(
                    "the installed policy determines whether an input volume is required".into(),
                );
            }
            let images = config.data.join("images");
            let image = approved_file(&images, &image)?;
            validate_base_image(&image)?;
            let input = input
                .map(|name| approved_file(&images, &name))
                .transpose()?;
            let row = registry.enroll(&Enrolled {
                id: Uuid::new_v4(),
                profile,
                policy_digest,
                image_digest: digest_file(&image)?,
                image,
                input_digest: input.as_deref().map(digest_file).transpose()?,
                input,
                broker,
            })?;
            (
                json!(row),
                Some((row.enrollment.id, "WORKLOAD_ENROLLED", "VERIFIED")),
            )
        }
        Request::Start { id } => {
            let row = lifecycle.start(id, |row| config.overlay(row))?;
            attach_gateway(registry, config, &row)?;
            (json!(row), Some((id, "WORKLOAD_STARTED", "VERIFIED")))
        }
        Request::Status { id } => (
            lifecycle
                .status(id)?
                .map_or(json!({"mode":"UNMANAGED"}), |row| json!(row)),
            None,
        ),
        Request::Verify { id } => {
            let status = lifecycle.verify(id)?;
            (
                json!({"id": id, "guest_network": status}),
                Some((id, "HOST_NETWORK_OBSERVED", status.as_str())),
            )
        }
        Request::Pause { id } => {
            let row = lifecycle.pause(id)?;
            if let Err(error) = broker::stop(registry, Some(id)) {
                let _ = Lifecycle::new(registry, &vm).contain(id, true);
                return Err(error);
            }
            (json!(row), Some((id, "WORKLOAD_PAUSED", "VERIFIED")))
        }
        Request::Resume { id } => {
            config.validate_enrolled(&lifecycle.status(id)?.ok_or("unmanaged workload")?)?;
            let row = lifecycle.resume(id)?;
            attach_gateway(registry, config, &row)?;
            (json!(row), Some((id, "WORKLOAD_RESUMED", "VERIFIED")))
        }
        Request::Contain { id } | Request::Terminate { id } => {
            let terminate = matches!(req, Request::Terminate { .. });
            let report = lifecycle.contain(id, terminate)?;
            let mode = if terminate {
                report.shutdown
            } else {
                report.guest_network
            };
            let result = if report.broker_cutoff == alethic_guardd::lifecycle::Observation::Verified
            {
                mode.as_str()
            } else {
                "UNKNOWN"
            };
            (
                json!(report),
                Some((
                    id,
                    if terminate {
                        "WORKLOAD_TERMINATED"
                    } else {
                        "CONTAINMENT_OBSERVED"
                    },
                    result,
                )),
            )
        }
        Request::Release { id } => {
            config.validate_enrolled(&lifecycle.status(id)?.ok_or("unmanaged workload")?)?;
            (
                json!(lifecycle.release(id)?),
                Some((id, "WORKLOAD_RELEASED", "VERIFIED")),
            )
        }
        Request::EffectStatus { id, request } => (registry.effect_status(id, request)?, None),
        Request::ReconcileReceipt {
            id,
            request,
            key,
            payload_sha256,
        } => {
            registry.reconcile_receipt(id, request, key, &payload_sha256)?;
            (registry.effect_status(id, request)?, None)
        }
        Request::EvidencePage { id, after } => {
            registry.get(id)?.ok_or("unmanaged workload")?;
            (
                json!({"events": registry.observation_page(id, after)?}),
                None,
            )
        }
        _ => return Err("broker operations require a bound gateway identity".into()),
    };
    if let Some((id, event_type, status)) = event {
        registry.record_host_observation(id, event_type, status)?;
    }
    Ok(result)
}

fn load_collector(path: &Path) -> GuardResult<CollectorConfig> {
    let dir = path.parent().ok_or("missing collector config parent")?;
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid config filename")?;
    let path = approved_file(dir, file)?;
    if path.metadata()?.len() > 4096 {
        return Err("collector configuration exceeds maximum size".into());
    }
    let config: CollectorConfig = serde_json::from_slice(&fs::read(path)?)?;
    let binary = &config.gateway;
    if !binary.is_absolute()
        || !binary.is_file()
        || fs::metadata(binary)?.uid() != 0
        || fs::metadata(binary)?.mode() & 0o022 != 0
    {
        return Err("gateway executable must be trusted host software".into());
    }
    if !config.controller_socket.is_absolute()
        || config
            .ca_file
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
    {
        return Err("expected absolute controller socket and CA paths".into());
    }
    let collector = Collector::parse_url(&config.target)?;
    collector.resolve(&config.addresses)?;
    Ok(config)
}

fn serve(config: Config) -> GuardResult<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("guardd must run as host root".into());
    }
    for directory in [
        &config.data,
        &config.policies,
        &config.data.join("run"),
        &config.data.join("state"),
        &config
            .socket
            .parent()
            .ok_or("missing socket parent")?
            .to_path_buf(),
    ] {
        if !directory.is_absolute() {
            return Err("daemon paths must be absolute".into());
        }
        secure_directory(directory)?;
    }
    let state = config.data.join("state");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join("guardd.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut registry = Registry::open(&state.join("guard.sqlite3"))?;
    broker::stop(&mut registry, None)?;
    registry.recover_effects()?;
    Lifecycle::new(&mut registry, &Libvirt).reconcile()?;

    match fs::symlink_metadata(&config.socket) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => {
            if std::os::unix::net::UnixStream::connect(&config.socket).is_ok() {
                return Err("another process owns the configured socket".into());
            }
            fs::remove_file(&config.socket)?;
        }
        Ok(_) => return Err("refusing to replace an unexpected socket path".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&config.socket)?;
    let mode = if config.collector.is_some() {
        let path = std::ffi::CString::new(config.socket.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::chown(path.as_ptr(), 0, BROKER_GROUP) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        0o660
    } else {
        0o600
    };
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(mode))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let request = configure(&stream).and_then(|_| {
            let uid = peer_uid(&stream)?;
            if uid != 0 {
                registry.gateway_by_uid(uid)?;
            }
            let request = read_frame(&stream)?;
            handle(request, &mut registry, &config, uid)
        });
        let envelope = match request {
            Ok(result) => json!({"ok": true, "result": result}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
        if let Err(error) = write_frame(&mut stream, &envelope) {
            eprintln!("operator response failed: {error}");
        }
    }
    Ok(())
}

fn run() -> GuardResult<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let config =
        match args.as_slice() {
            [] => Config {
                data: "/var/lib/alethic-guard".into(),
                policies: "/etc/alethic-guard/policies".into(),
                socket: "/run/alethic-guard/operator.sock".into(),
                collector: None,
            },
            [data, policies, socket] => Config {
                data: data.into(),
                policies: policies.into(),
                socket: socket.into(),
                collector: None,
            },
            [data, policies, socket, collector] => Config {
                data: data.into(),
                policies: policies.into(),
                socket: socket.into(),
                collector: Some(load_collector(Path::new(collector))?),
            },
            _ => return Err(
                "usage: alethic-guardd [DATA_DIR POLICY_DIR OPERATOR_SOCKET [COLLECTOR_CONFIG]]"
                    .into(),
            ),
        };
    serve(config)
}

fn main() -> std::process::ExitCode {
    // Secure permissions on database sidecars, private overlays and the socket
    // before any file is created. libvirt grants its emulator scoped disk access.
    unsafe {
        libc::umask(0o077);
    }
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("alethic-guardd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
