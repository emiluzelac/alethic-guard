use crate::{
    GuardResult,
    emergency::Fences,
    evidence::{self, EventFields},
    vm::{DomainSpec, Hypervisor, VmState, verify_domain},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Enrolled {
    pub id: Uuid,
    pub profile: String,
    pub policy_digest: String,
    pub image: PathBuf,
    pub image_digest: String,
    pub input: Option<PathBuf>,
    pub input_digest: Option<String>,
    #[serde(default)]
    pub broker: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Mode {
    Ready,
    Starting,
    Running,
    Paused,
    Containing,
    Contained,
    Terminated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Observation {
    Verified,
    Failed,
    Unknown,
}

impl Observation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Workload {
    pub enrollment: Enrolled,
    pub mode: Mode,
    pub epoch: u64,
    pub generation: u64,
    pub overlay: Option<PathBuf>,
    #[serde(default)]
    pub runtime_base: Option<PathBuf>,
    #[serde(default)]
    pub runtime_input: Option<PathBuf>,
    pub terminating: bool,
}

pub struct LaunchDisks {
    pub overlay: PathBuf,
    pub base: PathBuf,
    pub input: Option<PathBuf>,
}

impl Workload {
    pub fn domain(&self) -> GuardResult<DomainSpec> {
        Ok(DomainSpec {
            id: self.enrollment.id,
            base: self
                .runtime_base
                .clone()
                .unwrap_or_else(|| self.enrollment.image.clone()),
            broker: self.enrollment.broker,
            overlay: self.overlay.clone().ok_or("missing runtime overlay")?,
            input: if self.runtime_base.is_some() {
                self.runtime_input.clone()
            } else {
                self.enrollment.input.clone()
            },
        })
    }

    fn revoke(&mut self) -> GuardResult<()> {
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or("revocation epoch exhausted")?;
        Ok(())
    }

    fn begin_containment(&mut self, terminate: bool) -> GuardResult<()> {
        if !matches!(
            self.mode,
            Mode::Containing | Mode::Contained | Mode::Terminated
        ) {
            self.revoke()?;
        }
        self.terminating |= terminate;
        self.mode = Mode::Containing;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ContainmentReport {
    pub guest_network: Observation,
    pub admissions: Observation,
    pub broker_cutoff: Observation,
    pub shutdown: Observation,
    pub epoch: u64,
    pub mode: Mode,
}

pub struct Registry {
    pub(crate) conn: Connection,
}

#[derive(Debug, Serialize)]
pub struct HostRecoveryReport {
    pub id: Uuid,
    pub admissions: Observation,
    pub broker_cutoff: Observation,
    pub shutdown: Observation,
    pub record: Observation,
}

impl HostRecoveryReport {
    pub fn verified(&self) -> bool {
        [
            self.admissions,
            self.broker_cutoff,
            self.shutdown,
            self.record,
        ]
        .into_iter()
        .all(|observation| observation == Observation::Verified)
    }
}

impl Registry {
    pub fn open(path: &Path) -> GuardResult<Self> {
        Self::connect(Connection::open(path)?)
    }

    pub fn memory() -> GuardResult<Self> {
        Self::connect(Connection::open_in_memory()?)
    }

    pub fn open_for_recovery(path: &Path) -> GuardResult<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        Ok(Self { conn })
    }

    fn connect(conn: Connection) -> GuardResult<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS workloads (id TEXT PRIMARY KEY, record TEXT NOT NULL);",
        )?;
        crate::effect::initialize(&conn)?;
        crate::broker::initialize(&conn)?;
        crate::gateway_process::initialize(&conn)?;
        Ok(Self { conn })
    }

    pub fn enroll(&mut self, enrolled: &Enrolled) -> GuardResult<Workload> {
        let row = Workload {
            enrollment: enrolled.clone(),
            mode: Mode::Ready,
            epoch: 0,
            generation: 0,
            overlay: None,
            runtime_base: None,
            runtime_input: None,
            terminating: false,
        };
        self.conn.execute(
            "INSERT INTO workloads (id, record) VALUES (?1, ?2)",
            params![enrolled.id.to_string(), serde_json::to_string(&row)?],
        )?;
        Ok(row)
    }

    pub fn get(&self, id: Uuid) -> GuardResult<Option<Workload>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT record FROM workloads WHERE id = ?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(raw.as_deref().map(serde_json::from_str).transpose()?)
    }

    fn save(&mut self, item: &Workload) -> GuardResult<()> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::update_workload(&txn, item)?;
        txn.commit()?;
        Ok(())
    }

    fn update_workload(conn: &Connection, item: &Workload) -> GuardResult<()> {
        if conn.execute(
            "UPDATE workloads SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(item)?, item.enrollment.id.to_string()],
        )? != 1
        {
            return Err("enrollment disappeared".into());
        }
        Ok(())
    }

    pub fn all(&self) -> GuardResult<Vec<Workload>> {
        let mut query = self.conn.prepare("SELECT record FROM workloads")?;
        let raw = query.query_map([], |row| row.get::<_, String>(0))?;
        raw.map(|record| Ok(serde_json::from_str(&record?)?))
            .collect()
    }

    pub fn recover_host(
        &mut self,
        id: Uuid,
        fence: impl FnOnce(Uuid) -> GuardResult<()> + Send,
        stop: impl FnOnce(Uuid) -> GuardResult<bool> + Send,
    ) -> GuardResult<HostRecoveryReport> {
        let mut item = self.get(id)?.ok_or("unknown workload")?;
        if item.enrollment.id != id {
            return Err("registry enrollment identity mismatch".into());
        }
        let observe = |step: &str, result: GuardResult<bool>| match result {
            Ok(true) => Observation::Verified,
            Ok(false) => Observation::Failed,
            Err(error) => {
                eprintln!("host recovery {step} for {id}: {error}");
                Observation::Unknown
            }
        };
        let (intent, admissions, broker_cutoff, shutdown) = std::thread::scope(|scope| {
            // The daemon lock prevents new effects during offline recovery.
            // Start VM shutdown even if storage or network cleanup stalls.
            let vm = scope.spawn(move || observe("shutdown", stop(id)));
            let fence = scope.spawn(move || observe("admissions fence", fence(id).map(|()| true)));
            let broker_cutoff = observe(
                "broker cutoff",
                crate::broker::stop(self, Some(id)).map(|()| true),
            );
            let intent = item.begin_containment(true).and_then(|()| self.save(&item));
            let admissions = fence.join().unwrap_or(Observation::Unknown);
            let shutdown = vm.join().unwrap_or(Observation::Unknown);
            (intent, admissions, broker_cutoff, shutdown)
        });
        let completed = [admissions, broker_cutoff, shutdown]
            .into_iter()
            .all(|observation| observation == Observation::Verified);

        let recorded = intent.and_then(|()| {
            if broker_cutoff == Observation::Verified {
                self.recover_workload_effects(Some(id))?;
            }
            let txn = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            if completed {
                item.mode = Mode::Terminated;
                Self::update_workload(&txn, &item)?;
            }
            evidence::append(
                &txn,
                &item,
                EventFields {
                    event_type: "HOST_RECOVERY_OBSERVED",
                    observer: "guardd_recovery",
                    assurance: "HOST_VERIFIED",
                    request_id: None,
                    decision_id: None,
                    result: if completed {
                        "TERMINATED"
                    } else {
                        "INCOMPLETE"
                    },
                },
            )?;
            txn.commit()?;
            Ok(())
        });
        Ok(HostRecoveryReport {
            id,
            admissions,
            broker_cutoff,
            shutdown,
            record: observe("registry and journal", recorded.map(|()| true)),
        })
    }
}

enum ActiveBoundary {
    Verified,
    Drift(Box<dyn std::error::Error>),
}

pub struct Lifecycle<'a, H> {
    registry: &'a mut Registry,
    vm: &'a H,
    fences: Option<&'a Fences>,
}

impl<'a, H: Hypervisor> Lifecycle<'a, H> {
    pub fn new(registry: &'a mut Registry, vm: &'a H) -> Self {
        Self {
            registry,
            vm,
            fences: None,
        }
    }

    pub fn with_fences(mut self, fences: &'a Fences) -> Self {
        self.fences = Some(fences);
        self
    }

    fn guest_mutation(&self, id: Uuid, run: impl FnOnce() -> GuardResult<()>) -> GuardResult<()> {
        match self.fences {
            Some(fences) => fences.guest_operation(id, run),
            None => run(),
        }
    }

    pub fn status(&self, id: Uuid) -> GuardResult<Option<Workload>> {
        self.registry.get(id)
    }

    fn known(&self, id: Uuid) -> GuardResult<Workload> {
        self.registry
            .get(id)?
            .ok_or_else(|| "unmanaged workload".into())
    }

    fn compare_active(&self, item: &Workload) -> GuardResult<ActiveBoundary> {
        let id = item.enrollment.id;
        if !self.vm.is_transient(id)? {
            return Ok(ActiveBoundary::Drift(
                "domain persists outside Guard lifecycle authority".into(),
            ));
        }
        let xml = self.vm.active_xml(id)?;
        let spec = item.domain()?;
        Ok(match verify_domain(&xml, &spec) {
            Ok(()) => ActiveBoundary::Verified,
            Err(error) => ActiveBoundary::Drift(error),
        })
    }

    fn verify_active(&self, item: &Workload) -> GuardResult<()> {
        match self.compare_active(item)? {
            ActiveBoundary::Verified => Ok(()),
            ActiveBoundary::Drift(error) => Err(error),
        }
    }

    pub fn start(
        &mut self,
        id: Uuid,
        provision: impl FnOnce(&Workload) -> GuardResult<LaunchDisks>,
    ) -> GuardResult<Workload> {
        self.start_guarded(id, provision, || Ok(()))
    }

    pub fn start_guarded(
        &mut self,
        id: Uuid,
        provision: impl FnOnce(&Workload) -> GuardResult<LaunchDisks>,
        admit: impl Fn() -> GuardResult<()>,
    ) -> GuardResult<Workload> {
        let mut item = self.known(id)?;
        if item.mode != Mode::Ready || !self.vm.verify_absent(id)? {
            return Err("workload requires an explicit release or is already active".into());
        }
        item.generation = item
            .generation
            .checked_add(1)
            .ok_or("launch generation exhausted")?;
        item.mode = Mode::Starting;
        self.registry.save(&item)?;
        let start = (|| {
            let disks = provision(&item)?;
            item.overlay = Some(disks.overlay);
            item.runtime_base = Some(disks.base);
            item.runtime_input = disks.input;
            self.registry.save(&item)?;
            let domain = item.domain()?;
            self.guest_mutation(id, || {
                admit()?;
                self.vm.create_paused(&domain)
            })?;
            if self.vm.state(id)? != VmState::Paused {
                return Err("domain did not start paused".into());
            }
            self.verify_active(&item)?;
            self.guest_mutation(id, || {
                admit()?;
                self.vm.resume(id)
            })?;
            if self.vm.state(id)? != VmState::Running {
                return Err("domain failed to reach running state".into());
            }
            admit()?;
            item.mode = Mode::Running;
            self.registry.save(&item)
        })();
        if let Err(error) = start {
            // Preserve the failure and persist the containment transition even
            // when startup reached only part of the hypervisor operation.
            let report = self.contain(id, true);
            if let Ok(mut report) = report {
                if report.shutdown == Observation::Verified
                    && report.broker_cutoff == Observation::Verified
                {
                    item = self.known(id)?;
                    item.mode = Mode::Contained;
                    self.registry.save(&item)?;
                    report.mode = item.mode;
                }
                return Err(
                    format!("start failed: {error}; cleanup: {:?}", report.shutdown).into(),
                );
            }
            return Err(format!("start failed: {error}; containment pending").into());
        }
        Ok(item)
    }

    fn observe_guest(&self, item: &Workload) -> Observation {
        let id = item.enrollment.id;
        match self.vm.state(id) {
            Ok(VmState::Absent) => match self.vm.verify_absent(id) {
                Ok(true) => Observation::Verified,
                Ok(false) => Observation::Failed,
                Err(_) => Observation::Unknown,
            },
            Ok(_) => match self.compare_active(item) {
                Ok(ActiveBoundary::Verified) => Observation::Verified,
                Ok(ActiveBoundary::Drift(_)) => Observation::Failed,
                Err(_) => Observation::Unknown,
            },
            Err(_) => Observation::Unknown,
        }
    }

    pub fn verify(&mut self, id: Uuid) -> GuardResult<Observation> {
        let item = self.known(id)?;
        let observed = self.observe_guest(&item);
        if observed != Observation::Verified {
            self.contain(id, true)?;
        }
        Ok(observed)
    }

    pub fn require_running_boundary(&mut self, id: Uuid) -> GuardResult<()> {
        let item = self.known(id)?;
        if item.mode != Mode::Running {
            return Err("workload is not admitted".into());
        }
        if self.vm.state(id).ok() != Some(VmState::Running) || self.verify_active(&item).is_err() {
            self.contain(id, true)?;
            return Err("live guest boundary could not be verified".into());
        }
        Ok(())
    }

    pub fn pause(&mut self, id: Uuid) -> GuardResult<Workload> {
        let mut item = self.known(id)?;
        if item.mode != Mode::Running {
            return Err("pause requires a running workload".into());
        }
        item.mode = Mode::Paused;
        item.revoke()?;
        self.registry.save(&item)?;
        if self.vm.suspend(id).is_err() || self.vm.state(id).ok() != Some(VmState::Paused) {
            self.contain(id, true)?;
            return Err("unable to verify the pause".into());
        }
        Ok(item)
    }

    pub fn resume(&mut self, id: Uuid) -> GuardResult<Workload> {
        let mut item = self.known(id)?;
        if item.mode != Mode::Paused || self.vm.state(id)? != VmState::Paused {
            return Err("resume requires a verified paused workload".into());
        }
        if self.verify_active(&item).is_err() {
            self.contain(id, true)?;
            return Err("unable to verify the paused domain".into());
        }
        item.mode = Mode::Starting;
        self.registry.save(&item)?;
        if self.guest_mutation(id, || self.vm.resume(id)).is_err()
            || self.vm.state(id).ok() != Some(VmState::Running)
        {
            self.contain(id, true)?;
            return Err("unable to verify the resumed domain".into());
        }
        item.mode = Mode::Running;
        if let Err(error) = self.registry.save(&item) {
            if let Err(cleanup) = self.contain(id, true) {
                eprintln!("resumed VM containment for {id}: {cleanup}");
            }
            return Err(error);
        }
        Ok(item)
    }

    pub fn contain(&mut self, id: Uuid, terminate: bool) -> GuardResult<ContainmentReport> {
        let mut item = self.known(id)?;
        item.begin_containment(terminate)?;
        let persisted = self.registry.save(&item);
        // Attempt the host network cutoff even if the lifecycle write failed.
        let cutoff = crate::broker::stop(self.registry, Some(id));
        let broker_cutoff = match &cutoff {
            Ok(()) => Observation::Verified,
            Err(error) => {
                eprintln!("gateway containment for {id}: {error}");
                Observation::Unknown
            }
        };
        // Fence admissions and cut off the broker before waiting for libvirt.
        let mut guest_network = self.observe_guest(&item);
        let absent = match self.vm.state(id) {
            Ok(VmState::Absent) => true,
            Ok(_) => false,
            Err(_) => {
                guest_network = Observation::Unknown;
                false
            }
        };
        item.terminating |= guest_network != Observation::Verified;
        let mut shutdown = Observation::Unknown;
        if item.terminating || persisted.is_err() || absent {
            if self.vm.verify_absent(id).ok() != Some(true) {
                let _ = self.vm.destroy(id);
            }
            shutdown = match self.vm.verify_absent(id) {
                Ok(true) => Observation::Verified,
                Ok(false) => Observation::Failed,
                Err(_) => Observation::Unknown,
            };
        }
        if absent && shutdown != Observation::Verified {
            guest_network = shutdown;
            item.terminating = true;
        }
        persisted?;
        if cutoff.is_ok() {
            self.registry.recover_workload_effects(Some(id))?;
        }
        if shutdown == Observation::Verified
            && item.terminating
            && broker_cutoff == Observation::Verified
        {
            item.mode = Mode::Terminated;
        } else if !item.terminating && broker_cutoff == Observation::Verified {
            item.mode = Mode::Contained;
        }
        self.registry.save(&item)?;
        Ok(ContainmentReport {
            guest_network: if shutdown == Observation::Verified {
                Observation::Verified
            } else {
                guest_network
            },
            admissions: Observation::Verified,
            broker_cutoff,
            shutdown,
            epoch: item.epoch,
            mode: item.mode,
        })
    }

    pub fn release(&mut self, id: Uuid) -> GuardResult<Workload> {
        let item = self.verify_releasable(id)?;
        self.complete_release(item)
    }

    pub fn verify_releasable(&self, id: Uuid) -> GuardResult<Workload> {
        let item = self.known(id)?;
        if !matches!(item.mode, Mode::Contained | Mode::Terminated) || !self.vm.verify_absent(id)? {
            return Err("release requires a contained workload with verified shutdown".into());
        }
        Ok(item)
    }

    pub fn complete_release(&mut self, mut item: Workload) -> GuardResult<Workload> {
        item.mode = Mode::Ready;
        item.overlay = None;
        item.runtime_base = None;
        item.runtime_input = None;
        item.terminating = false;
        self.registry.save(&item)?;
        Ok(item)
    }

    pub fn reconcile(&mut self) -> GuardResult<()> {
        let mut errors = Vec::new();
        for item in self.registry.all()? {
            let id = item.enrollment.id;
            let result = (|| -> GuardResult<()> {
                if item.mode != Mode::Ready || !self.vm.verify_absent(id)? {
                    let result = self.contain(id, true)?;
                    if result.shutdown != Observation::Verified
                        || result.broker_cutoff != Observation::Verified
                    {
                        return Err("could not verify shutdown and broker cutoff".into());
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                errors.push(format!("startup reconciliation for {id}: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n").into())
        }
    }
}
