//! Host-only mediation. Guest requests contain no host authority.
use crate::{
    GuardResult,
    auth::peer_uid,
    collector::{BROKER_GROUP, Collector, CollectorConfig, GuestRequest},
    effect::{Action, Governance},
    emergency::Fences,
    evidence,
    lifecycle::{Mode, Registry, Workload},
    network::Sandbox,
    protocol::{configure, read_frame, write_frame},
    vm::{Hypervisor, Libvirt, broker_socket},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
};
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub struct Binding {
    pub id: Uuid,
    pub generation: u64,
    pub slot: u16,
    pub active: bool,
}

impl Binding {
    pub fn uid(self) -> u32 {
        BROKER_GROUP + u32::from(self.slot)
    }
    pub fn sandbox(self) -> GuardResult<Sandbox> {
        Sandbox::new(self.slot)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub action: Action,
    pub nonce: Uuid,
    pub dial: SocketAddr,
}

pub fn initialize(conn: &Connection) -> GuardResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS gateway_bindings (
             slot INTEGER PRIMARY KEY AUTOINCREMENT, workload TEXT NOT NULL,
             generation INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0,
             retired INTEGER NOT NULL DEFAULT 0
         );",
    )?;
    Ok(())
}

impl Registry {
    pub fn reserve_gateway(&mut self, item: &Workload) -> GuardResult<Binding> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        txn.execute(
            "INSERT INTO gateway_bindings (workload, generation) VALUES (?1, ?2)",
            params![item.enrollment.id.to_string(), item.generation],
        )?;
        let slot = u16::try_from(txn.last_insert_rowid())?;
        let binding = Binding {
            id: item.enrollment.id,
            generation: item.generation,
            slot,
            active: false,
        };
        binding.sandbox()?.ensure_clean()?;
        if let Ok(users) = std::fs::read_to_string("/etc/passwd") {
            if users.lines().any(|line| {
                line.split(':').nth(2).and_then(|id| id.parse::<u32>().ok()) == Some(binding.uid())
            }) {
                return Err("reserved gateway UID is assigned to a host account".into());
            }
        } else {
            return Err("cannot verify reserved gateway UID".into());
        }
        txn.commit()?;
        Ok(binding)
    }

    pub fn bindings(&self, id: Option<Uuid>) -> GuardResult<Vec<Binding>> {
        let mut statement = self.conn.prepare(
            "SELECT workload, generation, slot, active FROM gateway_bindings
             WHERE retired=0 AND (?1 IS NULL OR workload=?1)",
        )?;
        let rows = statement.query_map([id.map(|value| value.to_string())], |record| {
            Ok((
                record.get::<_, String>(0)?,
                record.get::<_, u64>(1)?,
                record.get::<_, u16>(2)?,
                record.get::<_, bool>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, generation, slot, active) = row?;
            Ok(Binding {
                id: Uuid::parse_str(&id)?,
                generation,
                slot,
                active,
            })
        })
        .collect()
    }

    fn cutoff_slots(&self, id: Option<Uuid>) -> GuardResult<Vec<rusqlite::Result<u16>>> {
        // Cutoff uses only the slot. Keep row errors separate so the sweep can continue.
        let mut statement = self.conn.prepare(
            "SELECT slot FROM gateway_bindings WHERE retired=0 AND (?1 IS NULL OR workload=?1)",
        )?;
        let rows = statement.query_map([id.map(|value| value.to_string())], |row| row.get(0))?;
        Ok(rows.collect())
    }

    pub fn set_gateway(
        &mut self,
        binding: Binding,
        active: bool,
        retired: bool,
    ) -> GuardResult<()> {
        self.set_gateway_slot(binding.slot, active, retired)
    }

    fn set_gateway_slot(&mut self, slot: u16, active: bool, retired: bool) -> GuardResult<()> {
        self.conn.execute(
            "UPDATE gateway_bindings SET active=?1, retired=?2 WHERE slot=?3",
            params![active, retired, slot],
        )?;
        Ok(())
    }

    pub fn gateway_by_uid(&self, uid: u32) -> GuardResult<Binding> {
        let slot = uid
            .checked_sub(BROKER_GROUP)
            .ok_or("unrecognized gateway peer")?;
        let row: Option<(String, u64, u16)> = self.conn.query_row(
            "SELECT workload, generation, slot FROM gateway_bindings WHERE active=1 AND retired=0 AND slot=?1",
            [slot], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let (id, generation, slot) = row.ok_or("unrecognized gateway peer")?;
        Ok(Binding {
            id: Uuid::parse_str(&id)?,
            generation,
            slot,
            active: true,
        })
    }
}

fn controller_call<T: DeserializeOwned>(
    config: &CollectorConfig,
    request: &impl Serialize,
) -> GuardResult<T> {
    let mut socket = UnixStream::connect(&config.controller_socket)?;
    configure(&socket)?;
    if config.controller_uid == 0 || peer_uid(&socket)? != config.controller_uid {
        return Err("controller has an unexpected host identity".into());
    }
    write_frame(&mut socket, request)?;
    read_frame(&socket)
}

pub fn controller_session(config: &CollectorConfig) -> GuardResult<Uuid> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Health {
        ok: bool,
        session: Uuid,
    }
    let response: Health = controller_call(config, &json!({"op": "ping"}))?;
    if !response.ok {
        return Err("controller refused health exchange".into());
    }
    Ok(response.session)
}

pub fn prepare(
    registry: &mut Registry,
    config: &CollectorConfig,
    peer: u32,
    request: GuestRequest,
    fences: &Fences,
) -> GuardResult<Prepared> {
    let binding = registry.gateway_by_uid(peer)?;
    let row = registry.get(binding.id)?.ok_or("unenrolled gateway")?;
    if !row.enrollment.broker || row.mode != Mode::Running || row.generation != binding.generation {
        return Err("gateway generation is inactive".into());
    }
    let body_digest = request.payload_digest()?;
    let collector = Collector::parse_url(&config.target)?;
    let resolved = collector.resolve(&config.addresses)?;
    let dial = resolved
        .into_iter()
        .next()
        .ok_or("missing collector address")?;
    let action = Action {
        workload_id: binding.id,
        generation: binding.generation,
        policy_digest: row.enrollment.policy_digest,
        epoch: row.epoch,
        operation: request.operation,
        target: config.target.clone(),
        payload_sha256: body_digest,
        data_labels: vec!["public".into()],
        request_id: request.request_id,
        idempotency_key: Uuid::new_v4(),
    };
    let decision: Governance = controller_call(
        config,
        &json!({
            "action": action,
            "snapshot": {"digest": action.policy_digest, "allowed_target": config.target},
        }),
    )?;
    let now = evidence::monotonic_ns()?;
    let nonce = fences.with_open(binding.id, || {
        registry.issue_grant(&action, &decision, peer, now)
    })?;
    Ok(Prepared {
        action,
        nonce,
        dial,
    })
}

pub fn start(
    registry: &mut Registry,
    row: &Workload,
    config: &CollectorConfig,
    socket: &Path,
    fences: &Fences,
) -> GuardResult<Child> {
    let collector = Collector::parse_url(&config.target)?;
    collector.resolve(&config.addresses)?;
    controller_session(config)?;
    let binding = registry.reserve_gateway(row)?;
    let sandbox = binding.sandbox()?;
    // Publish the link identity before creating any network objects.
    fences.bind(binding.id, sandbox)?;
    sandbox.create()?;
    let xml = Libvirt.active_xml(row.enrollment.id)?;
    let path = broker_socket(&xml, &row.domain()?)?;
    let channel = UnixStream::connect(path)?;
    let source = channel.as_raw_fd();
    let mut process = Command::new("/usr/sbin/ip");
    process
        .args([
            "netns",
            "exec",
            &sandbox.namespace(),
            "/usr/bin/setpriv",
            "--reuid",
            &binding.uid().to_string(),
            "--regid",
            &BROKER_GROUP.to_string(),
            "--clear-groups",
            "--no-new-privs",
        ])
        .arg(&config.gateway)
        .arg(socket);
    if let Some(ca) = &config.ca_file {
        process.arg(ca);
    }
    process.env_clear().stdin(Stdio::null());
    // Only this broker inherits the already-connected QEMU endpoint. The
    // unprivileged process receives no path into libvirt's runtime directory.
    unsafe {
        process.pre_exec(move || {
            if libc::dup2(source, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    fences.enable(binding.id, || {
        sandbox.enable(&config.addresses, collector.port)
    })?;
    let mut child = process.spawn()?;
    if let Err(error) = registry.set_gateway(binding, true, false) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(child)
}

pub fn stop(registry: &mut Registry, id: Option<Uuid>) -> GuardResult<()> {
    stop_with(registry, id, Sandbox::seal, Sandbox::stop_helpers)
}

fn stop_with(
    registry: &mut Registry,
    id: Option<Uuid>,
    mut seal: impl FnMut(Sandbox) -> GuardResult<()>,
    mut stop_helpers: impl FnMut(Sandbox) -> GuardResult<()>,
) -> GuardResult<()> {
    let mut failures = Vec::new();
    for slot in registry.cutoff_slots(id)? {
        let slot = match slot {
            Ok(slot) => slot,
            Err(error) => {
                failures.push(format!("reading gateway slot: {error}"));
                continue;
            }
        };
        let persist = registry.set_gateway_slot(slot, false, false);
        let result = Sandbox::new(slot).and_then(|sandbox| {
            let cutoff = seal(sandbox);
            let stopped = stop_helpers(sandbox);
            cutoff?;
            stopped?;
            persist?;
            registry.set_gateway_slot(slot, false, true)
        });
        if let Err(error) = result {
            failures.push(format!("gateway slot {slot}: {error}"));
        }
    }
    if !failures.is_empty() {
        return Err(failures.join("\n").into());
    }
    Ok(())
}
