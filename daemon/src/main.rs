use alethic_guardd::{
    GuardResult,
    auth::peer_credentials,
    broker,
    collector::{BROKER_GROUP, Collector, CollectorConfig, GuestRequest},
    digest_file,
    effect::{Action, Outcome},
    emergency::{self, Fences},
    evidence,
    lifecycle::{Enrolled, LaunchDisks, Lifecycle, Registry, Workload},
    protocol::{configure, read_frame, write_frame},
    vm::{Libvirt, create_overlay, validate_base_image},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
        },
    },
    path::{Path, PathBuf},
    sync::Arc,
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
    ReapGateway {
        id: Uuid,
        generation: u64,
        pid: u32,
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
    emulator_uid: u32,
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
        use alethic_guardd::policy::{MAX_POLICY_BYTES, validate_compiled};

        let path = approved_file(&self.policies, &format!("{profile}.json"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o222 != 0 || meta.nlink() != 1 {
            return Err("installed policy must be an immutable regular file owned by root".into());
        }
        let mut document = Vec::new();
        file.take((MAX_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut document)?;
        let policy = validate_compiled(&document, profile)?;
        if let Some(target) = &policy.collector_target {
            let config = self
                .collector
                .as_ref()
                .ok_or("mediated API is disabled on host")?;
            if target != &config.target {
                return Err("collector policy differs from host target".into());
            }
        }
        Ok((
            policy.digest,
            policy.has_input,
            policy.collector_target.is_some(),
        ))
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

    fn overlay(&self, row: &Workload) -> GuardResult<LaunchDisks> {
        use alethic_guardd::artifact::pin_file;

        self.validate_enrolled(row)?;
        let run = self.data.join("run");
        let artifacts = run.join("artifacts");
        secure_directory(&artifacts)?;
        let stage = |source: &Path, digest: &str, extension: &str| -> GuardResult<PathBuf> {
            let key = digest
                .strip_prefix("sha256:")
                .ok_or("invalid registered image digest")?;
            if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("invalid registered image digest".into());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(source)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o222 != 0 {
                return Err("launch source is no longer an approved artifact".into());
            }
            let destination = artifacts.join(format!("{key}.{extension}"));
            pin_file(file, &destination, digest)?;
            alethic_guardd::artifact::restrict_to_emulator(&destination, self.emulator_uid)?;
            Ok(destination)
        };
        let base = stage(&row.enrollment.image, &row.enrollment.image_digest, "qcow2")?;
        validate_base_image(&base)?;
        let input = match (&row.enrollment.input, &row.enrollment.input_digest) {
            (None, None) => None,
            (Some(source), Some(digest)) => Some(stage(source, digest, "raw")?),
            _ => return Err("incomplete input provenance".into()),
        };
        let overlay = run.join(format!("{}-{}.qcow2", row.enrollment.id, row.generation));
        create_overlay(&overlay, &base)?;
        Ok(LaunchDisks {
            overlay,
            base,
            input,
        })
    }
}

fn broker_request(
    req: Request,
    registry: &mut Registry,
    config: &Config,
    uid: u32,
    fences: &Fences,
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
    if matches!(
        req,
        Request::BrokerPrepare { .. } | Request::BrokerRedeem { .. } | Request::BrokerCheck { .. }
    ) {
        fences.with_open(binding.id, || Ok(()))?;
        Lifecycle::new(registry, &Libvirt).require_running_boundary(binding.id)?;
    }
    match req {
        Request::BrokerPrepare { request } => Ok(json!(broker::prepare(
            registry, collector, uid, request, fences
        )?)),
        Request::BrokerRedeem { nonce, action } => {
            let session = broker::controller_session(collector)?;
            registry.authenticate_controller_session(nonce, session)?;
            fences.with_open(binding.id, || {
                registry.redeem_grant(nonce, &action, uid, evidence::monotonic_ns()?)
            })?;
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
            fences.with_open(binding.id, || {
                registry.check_dispatch(nonce, uid, evidence::monotonic_ns()?)
            })?;
            Ok(json!({}))
        }
        Request::BrokerFinish { nonce, outcome } => {
            registry.finish(nonce, uid, outcome)?;
            Ok(json!({}))
        }
        _ => Err("host root is required for operator operations".into()),
    }
}

fn attach_gateway(
    registry: &mut Registry,
    config: &Config,
    item: &Workload,
    fences: &Fences,
) -> GuardResult<()> {
    if let Err(error) = fences.with_open(item.enrollment.id, || Ok(())) {
        let _ = Lifecycle::new(registry, &Libvirt).contain(item.enrollment.id, true);
        return Err(error);
    }
    if !item.enrollment.broker {
        return Ok(());
    }
    let collector = config.collector.as_ref().ok_or("gateway disabled")?;
    match broker::start(registry, item, collector, &config.socket, fences) {
        Ok(mut child) => {
            if let Err(error) = registry.bind_gateway_process(item, child.id()) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = Lifecycle::new(registry, &Libvirt).contain(item.enrollment.id, true);
                return Err(error);
            }
            let socket = config.socket.clone();
            let id = item.enrollment.id;
            let generation = item.generation;
            let pid = child.id();
            thread::spawn(move || match child.wait() {
                Ok(_) => {
                    let notify = (|| -> GuardResult<()> {
                        let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
                        configure(&stream)?;
                        write_frame(
                            &mut stream,
                            &json!({"command":"reap_gateway","id":id,"generation":generation,"pid":pid}),
                        )?;
                        Ok(())
                    })();
                    if let Err(error) = notify {
                        eprintln!("gateway exit notification failed: {error}");
                    }
                }
                Err(error) => eprintln!("gateway wait failed: {error}"),
            });
            Ok(())
        }
        Err(error) => {
            let _ = Lifecycle::new(registry, &Libvirt).contain(item.enrollment.id, true);
            Err(error)
        }
    }
}

fn handle(
    req: Request,
    registry: &mut Registry,
    config: &Config,
    uid: u32,
    fences: &Fences,
) -> GuardResult<Value> {
    if uid != 0 {
        return broker_request(req, registry, config, uid, fences);
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
            fences.register(row.enrollment.id)?;
            (
                json!(row),
                Some((row.enrollment.id, "WORKLOAD_ENROLLED", "VERIFIED")),
            )
        }
        Request::Start { id } => {
            lifecycle.status(id)?.ok_or("unmanaged workload")?;
            fences.with_open(id, || Ok(()))?;
            let row = lifecycle.start(id, |row| config.overlay(row))?;
            attach_gateway(registry, config, &row, fences)?;
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
            registry.recover_workload_effects(Some(id))?;
            (json!(row), Some((id, "WORKLOAD_PAUSED", "VERIFIED")))
        }
        Request::Resume { id } => {
            let row = lifecycle.status(id)?.ok_or("unmanaged workload")?;
            fences.with_open(id, || Ok(()))?;
            config.validate_enrolled(&row)?;
            let row = lifecycle.resume(id)?;
            attach_gateway(registry, config, &row, fences)?;
            (json!(row), Some((id, "WORKLOAD_RESUMED", "VERIFIED")))
        }
        Request::Contain { id } | Request::Terminate { id } => {
            let terminate = matches!(req, Request::Terminate { .. });
            lifecycle.status(id)?.ok_or("unmanaged workload")?;
            let latched = fences.cutoff(id, |_| Ok(()));
            let report = lifecycle.contain(id, terminate)?;
            latched?;
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
                json!(fences.release(id, |latched| lifecycle.release_latched(id, latched))?),
                Some((id, "WORKLOAD_RELEASED", "VERIFIED")),
            )
        }
        Request::ReapGateway {
            id,
            generation,
            pid,
        } => {
            if registry.has_active_gateway_process(id, generation, pid)? {
                let report = Lifecycle::new(registry, &vm).contain(id, false)?;
                let status = report.broker_cutoff.as_str();
                (json!(report), Some((id, "GATEWAY_EXIT_OBSERVED", status)))
            } else {
                (json!({}), None)
            }
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
    secure_directory(
        binary
            .parent()
            .ok_or("gateway executable requires a protected parent")?,
    )?;
    let meta = fs::symlink_metadata(binary)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
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
    if let Some(ca) = &config.ca_file {
        let file = ca
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid CA filename")?;
        approved_file(ca.parent().ok_or("missing CA file parent")?, file)?;
    }
    let collector = Collector::parse_url(&config.target)?;
    collector.resolve(&config.addresses)?;
    Ok(config)
}

fn bind_socket(path: &Path) -> GuardResult<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err("another process owns the configured socket".into());
            }
            fs::remove_file(path)?;
        }
        Ok(_) => return Err("refusing to replace an unexpected socket path".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(UnixListener::bind(path)?)
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
    let artifacts = config.data.join("run/artifacts");
    match fs::create_dir(&artifacts) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    secure_directory(&artifacts)?;
    alethic_guardd::artifact::restrict_to_emulator(&artifacts, config.emulator_uid)?;
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

    let fence_path = state.join("emergency");
    match fs::create_dir(&fence_path) {
        Ok(()) => fs::File::open(&state)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    secure_directory(&fence_path)?;
    let fences = Arc::new(Fences::new(fence_path));
    // Startup closes every previous broker binding before serving either socket.
    for row in registry.all()? {
        fences.register(row.enrollment.id)?;
    }
    let cutoff_path = emergency::socket_path(&config.socket)?;
    let cutoff_listener = bind_socket(&cutoff_path)?;
    fs::set_permissions(&cutoff_path, fs::Permissions::from_mode(0o600))?;
    let listener = bind_socket(&config.socket)?;
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
    let cutoff_fences = Arc::clone(&fences);
    thread::spawn(move || emergency::serve(cutoff_listener, &cutoff_fences));
    for stream in listener.incoming() {
        let mut stream = stream?;
        let request = configure(&stream).and_then(|_| {
            let peer = peer_credentials(&stream)?;
            if peer.uid != 0 {
                let binding = registry.gateway_by_uid(peer.uid)?;
                registry.require_gateway_process(binding, peer)?;
            }
            let request = read_frame(&stream)?;
            handle(request, &mut registry, &config, peer.uid, &fences)
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

fn emulator_uid() -> GuardResult<u32> {
    let account = alethic_guardd::vm::command_with_timeout(
        "3s",
        "/usr/bin/getent",
        &[OsStr::new("passwd"), OsStr::new("libvirt-qemu")],
        None,
    )?;
    let mut fields = account.trim_end().split(':');
    if fields.next() != Some("libvirt-qemu") {
        return Err("expected the installed libvirt-qemu service account".into());
    }
    let uid = fields
        .nth(1)
        .ok_or("missing emulator UID")?
        .parse::<u32>()?;
    if uid == 0 || uid == u32::MAX {
        return Err("invalid emulator UID".into());
    }
    Ok(uid)
}

fn run() -> GuardResult<()> {
    let emulator_uid = emulator_uid()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let config =
        match args.as_slice() {
            [] => Config {
                data: "/var/lib/alethic-guard".into(),
                policies: "/etc/alethic-guard/policies".into(),
                socket: "/run/alethic-guard/operator.sock".into(),
                collector: None,
                emulator_uid,
            },
            [data, policies, socket] => Config {
                data: data.into(),
                policies: policies.into(),
                socket: socket.into(),
                collector: None,
                emulator_uid,
            },
            [data, policies, socket, collector] => Config {
                data: data.into(),
                policies: policies.into(),
                socket: socket.into(),
                collector: Some(load_collector(Path::new(collector))?),
                emulator_uid,
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
