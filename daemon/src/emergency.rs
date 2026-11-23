//! Root-only broker cutoff and guest shutdown outside the ordinary operator queue.

use crate::{
    GuardResult,
    auth::peer_uid,
    evidence::monotonic_ns,
    lifecycle::Observation,
    network::Sandbox,
    protocol::{configure, read_frame, write_frame},
    vm::Libvirt,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        fs::OpenOptionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

struct WorkloadGate {
    // Odd generations are latched. Every cutoff invalidates a pending release.
    generation: AtomicU64,
    transition: Mutex<NetworkState>,
    guest: Mutex<()>,
}

struct NetworkState {
    completed_cutoff: u64,
    sandbox: Option<Sandbox>,
}

impl WorkloadGate {
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn check(&self) -> GuardResult<()> {
        if self.generation() % 2 == 1 {
            return Err("workload emergency cutoff is latched".into());
        }
        Ok(())
    }

    fn latch(&self) -> GuardResult<u64> {
        // `try_update` is unavailable on the supported Rust 1.85 toolchain.
        #[allow(deprecated)]
        let previous = self
            .generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |version| {
                version.checked_add(2).map(|_| (version + 1) | 1)
            })
            .map_err(|_| "emergency cutoff generation exhausted")?;
        Ok((previous + 1) | 1)
    }
}

struct WorkerPermit(Arc<AtomicUsize>);

impl WorkerPermit {
    fn acquire(workers: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        #[allow(deprecated)]
        workers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()?;
        Some(Self(Arc::clone(workers)))
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

pub struct Fences {
    root: PathBuf,
    gates: Mutex<HashMap<Uuid, Arc<WorkloadGate>>>,
    cutoff_workers: Arc<AtomicUsize>,
}

impl Fences {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            gates: Mutex::new(HashMap::new()),
            cutoff_workers: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn marker(&self, id: Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }

    fn gate(&self, id: Uuid) -> GuardResult<Arc<WorkloadGate>> {
        if let Some(gate) = self.registered_gate(id)? {
            return Ok(gate);
        }
        let initial = u64::from(self.marker(id).try_exists()?);
        let mut gates = self
            .gates
            .lock()
            .map_err(|_| "emergency gate registry unavailable")?;
        Ok(Arc::clone(gates.entry(id).or_insert_with(|| {
            Arc::new(WorkloadGate {
                generation: AtomicU64::new(initial),
                transition: Mutex::new(NetworkState {
                    completed_cutoff: initial,
                    sandbox: None,
                }),
                guest: Mutex::new(()),
            })
        })))
    }

    pub fn register(&self, id: Uuid) -> GuardResult<()> {
        self.gate(id)?;
        Ok(())
    }

    pub fn bind(&self, id: Uuid, sandbox: Sandbox) -> GuardResult<()> {
        let gate = self.gate(id)?;
        let mut network = gate
            .transition
            .lock()
            .map_err(|_| "workload emergency gate unavailable")?;
        gate.check()?;
        network.sandbox = Some(sandbox);
        Ok(())
    }

    fn registered_gate(&self, id: Uuid) -> GuardResult<Option<Arc<WorkloadGate>>> {
        Ok(self
            .gates
            .lock()
            .map_err(|_| "emergency gate registry unavailable")?
            .get(&id)
            .cloned())
    }

    pub fn with_open<T>(&self, id: Uuid, run: impl FnOnce() -> GuardResult<T>) -> GuardResult<T> {
        let gate = self.gate(id)?;
        gate.check()?;
        let result = run()?;
        gate.check()?;
        Ok(result)
    }

    pub fn enable<T>(&self, id: Uuid, run: impl FnOnce() -> GuardResult<T>) -> GuardResult<T> {
        let gate = self.gate(id)?;
        let _network = gate
            .transition
            .lock()
            .map_err(|_| "workload emergency gate unavailable")?;
        gate.check()?;
        let result = run()?;
        gate.check()?;
        Ok(result)
    }

    pub fn guest_operation<T>(
        &self,
        id: Uuid,
        run: impl FnOnce() -> GuardResult<T>,
    ) -> GuardResult<T> {
        let gate = self.gate(id)?;
        let _guest = gate
            .guest
            .lock()
            .map_err(|_| "guest transition unavailable")?;
        gate.check()?;
        run()
    }

    pub fn cutoff<T>(
        &self,
        id: Uuid,
        cut: impl FnOnce(Option<Sandbox>) -> GuardResult<T>,
    ) -> GuardResult<T> {
        let gate = self.gate(id)?;
        let version = gate.latch()?;
        Self::complete_cutoff(&gate, &self.root, id, version, cut)
    }

    fn complete_cutoff<T>(
        gate: &WorkloadGate,
        root: &Path,
        id: Uuid,
        version: u64,
        cut: impl FnOnce(Option<Sandbox>) -> GuardResult<T>,
    ) -> GuardResult<T> {
        let mut network = gate
            .transition
            .lock()
            .map_err(|_| "workload emergency gate unavailable")?;
        if version < network.completed_cutoff {
            return Err("a newer emergency cutoff already completed".into());
        }
        let result = cut(network.sandbox);
        let durable = (|| -> GuardResult<()> {
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(root.join(id.to_string()))?;
            file.sync_all()?;
            File::open(root)?.sync_all()?;
            Ok(())
        })();
        durable?;
        let observed = result?;
        network.completed_cutoff = network.completed_cutoff.max(version);
        Ok(observed)
    }

    fn background_cutoff(
        &self,
        id: Uuid,
        gate: Arc<WorkloadGate>,
        cut: impl FnOnce(Option<Sandbox>) -> GuardResult<()> + Send + 'static,
    ) -> GuardResult<mpsc::Receiver<Observation>> {
        // Fence new grants before scheduling work that may block on the host.
        let version = gate.latch()?;
        let (send, receive) = mpsc::sync_channel(1);
        if let Some(permit) = WorkerPermit::acquire(&self.cutoff_workers, 8) {
            let root = self.root.clone();
            if let Err(error) = thread::Builder::new().spawn(move || {
                let _permit = permit;
                let observation = match Self::complete_cutoff(&gate, &root, id, version, cut) {
                    Ok(()) => Observation::Verified,
                    Err(error) => {
                        eprintln!("emergency cutoff for {id}: {error}");
                        Observation::Unknown
                    }
                };
                let _ = send.send(observation);
            }) {
                eprintln!("starting cutoff worker for {id}: {error}");
            }
        }
        Ok(receive)
    }

    pub fn emergency_terminate(
        &self,
        id: Uuid,
        cut: impl FnOnce(Option<Sandbox>) -> GuardResult<()> + Send + 'static,
        stop: impl FnOnce() -> GuardResult<bool>,
    ) -> GuardResult<serde_json::Value> {
        let gate = self.registered_gate(id)?.ok_or("unmanaged workload")?;
        // Even a stuck start or resume must not delay fencing broker admissions.
        let guest = gate.guest.try_lock().ok();
        let cutoff = self.background_cutoff(id, Arc::clone(&gate), cut)?;
        // Keep the transition guard through both observation timestamps.
        let shutdown = if guest.is_some() {
            match stop() {
                Ok(true) => Observation::Verified,
                Ok(false) => Observation::Failed,
                Err(error) => {
                    eprintln!("emergency VM shutdown for {id}: {error}");
                    Observation::Unknown
                }
            }
        } else {
            Observation::Unknown
        };
        let fenced = cutoff
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(Observation::Unknown);
        Ok(json!({
            "id": id,
            "admissions": fenced,
            "broker_cutoff": fenced,
            "shutdown": shutdown,
            "observed_at_unix_ns": unix_ns()?,
            "host_monotonic_ns": monotonic_ns()?,
        }))
    }

    pub fn release<T>(&self, id: Uuid, run: impl FnOnce() -> GuardResult<T>) -> GuardResult<T> {
        let gate = self
            .gates
            .lock()
            .map_err(|_| "emergency gate registry unavailable")?
            .get(&id)
            .cloned()
            .ok_or("unmanaged workload")?;
        let version = gate.generation();
        let result = run()?;
        let _guest = gate
            .guest
            .lock()
            .map_err(|_| "guest transition unavailable")?;
        let network = gate
            .transition
            .lock()
            .map_err(|_| "workload emergency gate unavailable")?;
        let released = version
            .checked_add(version % 2)
            .ok_or("release generation exhausted")?;
        if gate.generation() != version || (version % 2 == 1 && network.completed_cutoff != version)
        {
            return Err("a newer emergency cutoff interrupted release".into());
        }
        // Claim this release before removing its marker. A cutoff that wins the
        // generation race leaves the existing durable marker in place.
        gate.generation
            .compare_exchange(version, released, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "a newer emergency cutoff interrupted release")?;
        let durable = (|| -> io::Result<()> {
            let directory = File::open(&self.root)?;
            match fs::remove_file(self.marker(id)) {
                Ok(()) => directory.sync_all(),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        })();
        if let Err(error) = durable {
            // Leave the workload fenced on storage failure unless a newer
            // cutoff has already fenced it.
            let _ = gate.generation.compare_exchange(
                released,
                version,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            return Err(error.into());
        }
        Ok(result)
    }
}

pub fn socket_path(operator_socket: &Path) -> GuardResult<PathBuf> {
    let mut name = OsString::from(
        operator_socket
            .file_name()
            .ok_or("missing operator socket filename")?,
    );
    name.push(".emergency");
    Ok(operator_socket.with_file_name(name))
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Cutoff { id: Uuid },
    Terminate { id: Uuid },
}

fn unix_ns() -> GuardResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

fn handle(mut stream: UnixStream, fences: &Fences) {
    let response = (|| -> GuardResult<serde_json::Value> {
        configure(&stream)?;
        if peer_uid(&stream)? != 0 {
            return Err("host root is required for emergency operations".into());
        }
        let cut = |sandbox: Option<Sandbox>| sandbox.map_or(Ok(()), Sandbox::seal);
        let id = match read_frame(&stream)? {
            Request::Cutoff { id } => id,
            Request::Terminate { id } => {
                return fences.emergency_terminate(id, cut, || Libvirt::emergency_shutdown(id));
            }
        };
        let gate = fences.registered_gate(id)?.ok_or("unmanaged workload")?;
        let cutoff = fences.background_cutoff(id, gate, cut)?;
        let fenced = cutoff
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(Observation::Unknown);
        Ok(json!({
            "id": id,
            "admissions": fenced,
            "broker_cutoff": fenced,
            "observed_at_unix_ns": unix_ns()?,
            "host_monotonic_ns": monotonic_ns()?,
        }))
    })();
    let envelope = match response {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    };
    if let Err(error) = write_frame(&mut stream, &envelope) {
        eprintln!("emergency response failed: {error}");
    }
}

pub fn serve(listener: UnixListener, fences: &Arc<Fences>) {
    let workers = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("emergency accept failed: {error}");
                continue;
            }
        };
        let Some(permit) = WorkerPermit::acquire(&workers, 8) else {
            let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
            let _ = write_frame(
                &mut stream,
                &json!({
                    "ok": false,
                    "error": "emergency request capacity reached; retry this request",
                }),
            );
            continue;
        };
        let fences = Arc::clone(fences);
        if let Err(error) = thread::Builder::new().spawn(move || {
            let _permit = permit;
            handle(stream, &fences);
        }) {
            eprintln!("starting emergency request worker: {error}");
        }
    }
}
