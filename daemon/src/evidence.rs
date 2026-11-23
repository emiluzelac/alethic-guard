use crate::GuardResult;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u8,
    pub event_id: Uuid,
    pub sequence: u64,
    pub utc_unix_ms: u64,
    pub host_boot_id: String,
    pub host_monotonic_ns: u64,
    pub workload_id: Uuid,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub policy_digest: String,
    pub event_type: String,
    pub observer: String,
    pub assurance: String,
    pub request_id: Option<Uuid>,
    pub decision_id: Option<String>,
    pub result: String,
    pub prev_event_hash: String,
    pub event_hash: String,
}

pub struct EventFields<'a> {
    pub event_type: &'a str,
    pub observer: &'a str,
    pub assurance: &'a str,
    pub request_id: Option<Uuid>,
    pub decision_id: Option<&'a str>,
    pub result: &'a str,
}

pub fn initialize(conn: &Connection) -> GuardResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
             workload TEXT NOT NULL, sequence INTEGER NOT NULL, hash TEXT NOT NULL, body TEXT NOT NULL,
             PRIMARY KEY (workload, sequence)
         );
         CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
             BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
         CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
             BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;"
    )?;
    Ok(())
}

pub fn monotonic_ns() -> GuardResult<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut timestamp) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(u64::try_from(timestamp.tv_sec)? * 1_000_000_000 + u64::try_from(timestamp.tv_nsec)?)
}

pub fn append(
    conn: &Connection,
    workload: &crate::lifecycle::Workload,
    fields: EventFields<'_>,
) -> GuardResult<()> {
    let id = workload.enrollment.id;
    let previous: Option<(u64, String)> = conn
        .query_row(
            "SELECT sequence, hash FROM events WHERE workload = ?1 ORDER BY sequence DESC LIMIT 1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (last_sequence, prev_event_hash) = previous.unwrap_or((0, String::new()));
    let mut body = Event {
        schema_version: 1,
        event_id: Uuid::new_v4(),
        sequence: last_sequence
            .checked_add(1)
            .ok_or("evidence sequence exhausted")?,
        utc_unix_ms: u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
        host_boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        host_monotonic_ns: monotonic_ns()?,
        workload_id: id,
        generation: workload.generation,
        revocation_epoch: workload.epoch,
        policy_digest: workload.enrollment.policy_digest.clone(),
        event_type: fields.event_type.into(),
        observer: fields.observer.into(),
        assurance: fields.assurance.into(),
        request_id: fields.request_id,
        decision_id: fields.decision_id.map(str::to_owned),
        result: fields.result.into(),
        prev_event_hash,
        event_hash: String::new(),
    };
    body.event_hash = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&serde_json::to_value(&body)?)?)
    );
    conn.execute(
        "INSERT INTO events VALUES (?1, ?2, ?3, ?4)",
        params![
            id.to_string(),
            body.sequence,
            body.event_hash,
            serde_json::to_string(&body)?
        ],
    )?;
    Ok(())
}

pub fn page(conn: &Connection, workload: Uuid, after: u64) -> GuardResult<Vec<Event>> {
    let mut query = conn.prepare(
        "SELECT body FROM events WHERE workload = ?1 AND sequence > ?2 ORDER BY sequence LIMIT 25",
    )?;
    let rows = query.query_map(params![workload.to_string(), after], |row| {
        row.get::<_, String>(0)
    })?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

impl crate::lifecycle::Registry {
    pub fn observation_page(&self, workload: Uuid, after: u64) -> GuardResult<Vec<Event>> {
        page(&self.conn, workload, after)
    }

    pub fn record_gateway_denial(&mut self, id: Uuid, result: &str) -> GuardResult<()> {
        let row = self.get(id)?.ok_or("unknown workload")?;
        let txn = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        append(
            &txn,
            &row,
            EventFields {
                event_type: "GATEWAY_DENIED",
                observer: "gateway",
                assurance: "HOST_REPORTED",
                request_id: None,
                decision_id: None,
                result,
            },
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn record_host_observation(
        &mut self,
        id: Uuid,
        event_type: &str,
        result: &str,
    ) -> GuardResult<()> {
        let row = self.get(id)?.ok_or("unknown workload")?;
        let txn = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        append(
            &txn,
            &row,
            EventFields {
                event_type,
                observer: "guardd",
                assurance: "HOST_VERIFIED",
                request_id: None,
                decision_id: None,
                result,
            },
        )?;
        txn.commit()?;
        Ok(())
    }
}
