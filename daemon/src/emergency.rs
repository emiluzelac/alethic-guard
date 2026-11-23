//! Root-only broker cutoff independent of the ordinary operator queue.

use crate::{
    GuardResult,
    auth::peer_uid,
    evidence::monotonic_ns,
    network::Sandbox,
    protocol::{configure, read_frame, write_frame},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{fs::OpenOptionsExt, net::UnixListener},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

struct WorkloadGate {
    // Odd generations are latched. Every cutoff invalidates a pending release.
    generation: AtomicU64,
    transition: Mutex<NetworkState>,
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
}

pub struct Fences {
    root: PathBuf,
    gates: Mutex<HashMap<Uuid, Arc<WorkloadGate>>>,
}

impl Fences {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            gates: Mutex::new(HashMap::new()),
        }
    }

    fn marker(&self, id: Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }

    fn gate(&self, id: Uuid) -> GuardResult<Arc<WorkloadGate>> {
        let mut gates = self
            .gates
            .lock()
            .map_err(|_| "emergency gate registry unavailable")?;
        if let Some(gate) = gates.get(&id) {
            return Ok(Arc::clone(gate));
        }
        let initial = u64::from(self.marker(id).try_exists()?);
        let gate = Arc::new(WorkloadGate {
            generation: AtomicU64::new(initial),
            transition: Mutex::new(NetworkState {
                completed_cutoff: initial,
                sandbox: None,
            }),
        });
        gates.insert(id, Arc::clone(&gate));
        Ok(gate)
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

    fn is_registered(&self, id: Uuid) -> GuardResult<bool> {
        Ok(self
            .gates
            .lock()
            .map_err(|_| "emergency gate registry unavailable")?
            .contains_key(&id))
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

    pub fn cutoff<T>(
        &self,
        id: Uuid,
        cut: impl FnOnce(Option<Sandbox>) -> GuardResult<T>,
    ) -> GuardResult<T> {
        let gate = self.gate(id)?;
        // `try_update` is unavailable on the supported Rust 1.85 toolchain.
        #[allow(deprecated)]
        let previous = gate
            .generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |version| {
                version.checked_add(2).map(|_| (version + 1) | 1)
            })
            .map_err(|_| "emergency cutoff generation exhausted")?;
        let version = (previous + 1) | 1;
        let mut network = gate
            .transition
            .lock()
            .map_err(|_| "workload emergency gate unavailable")?;
        let result = cut(network.sandbox);
        let durable = (|| -> GuardResult<()> {
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.marker(id))?;
            file.sync_all()?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        durable?;
        let observed = result?;
        network.completed_cutoff = network.completed_cutoff.max(version);
        Ok(observed)
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
}

pub fn serve(listener: UnixListener, fences: &Fences) {
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("emergency accept failed: {error}");
                continue;
            }
        };
        let response = (|| -> GuardResult<serde_json::Value> {
            configure(&stream)?;
            if peer_uid(&stream)? != 0 {
                return Err("host root is required for emergency cutoff".into());
            }
            let Request::Cutoff { id } = read_frame(&stream)?;
            if !fences.is_registered(id)? {
                return Err("unmanaged workload".into());
            }
            fences.cutoff(id, |sandbox| {
                if let Some(sandbox) = sandbox {
                    sandbox.seal()?;
                }
                let observed_at_unix_ns =
                    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
                Ok(json!({
                    "id": id,
                    "admissions": "VERIFIED",
                    "broker_cutoff": "VERIFIED",
                    "observed_at_unix_ns": observed_at_unix_ns,
                    "host_monotonic_ns": monotonic_ns()?,
                }))
            })
        })();
        let envelope = match response {
            Ok(result) => json!({"ok": true, "result": result}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
        if let Err(error) = write_frame(&mut stream, &envelope) {
            eprintln!("emergency response failed: {error}");
        }
    }
}
