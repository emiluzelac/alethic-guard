use crate::{
    GuardResult,
    evidence::{self, EventFields},
    lifecycle::{Mode, Registry, Workload},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const GRANT_TTL_NS: u64 = 10_000_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub workload_id: Uuid,
    pub generation: u64,
    pub policy_digest: String,
    pub epoch: u64,
    pub operation: String,
    pub target: String,
    pub payload_sha256: String,
    pub data_labels: Vec<String>,
    pub request_id: Uuid,
    pub idempotency_key: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    pub session: Uuid,
    pub ok: bool,
    pub trace_id: String,
    pub code: String,
    pub proposal_id: String,
    pub action_id: Option<String>,
    pub evidence_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Started,
    Succeeded,
    Failed,
    OutcomeUnknown,
}

pub fn initialize(conn: &Connection) -> GuardResult<()> {
    evidence::initialize(conn)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS grants (
             nonce TEXT PRIMARY KEY, workload TEXT NOT NULL, request TEXT NOT NULL,
             owner INTEGER NOT NULL, action TEXT NOT NULL, expires INTEGER NOT NULL,
             decision TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
             UNIQUE (workload, request)
         );
         CREATE TABLE IF NOT EXISTS effects (
             workload TEXT NOT NULL, request TEXT NOT NULL, action TEXT NOT NULL,
             outcome TEXT NOT NULL, PRIMARY KEY (workload, request)
         );",
    )?;
    Ok(())
}

fn workload(conn: &Connection, id: Uuid) -> GuardResult<Workload> {
    let record: String = conn.query_row(
        "SELECT record FROM workloads WHERE id=?1",
        [id.to_string()],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_str(&record)?)
}

fn current(conn: &Connection, action: &Action) -> GuardResult<Workload> {
    let row = workload(conn, action.workload_id)?;
    if row.mode != Mode::Running
        || row.epoch != action.epoch
        || row.generation != action.generation
        || row.enrollment.policy_digest != action.policy_digest
    {
        return Err("workload generation, policy, or revocation epoch is ineligible".into());
    }
    Ok(row)
}

struct BoundGrant {
    owner: u32,
    action: Action,
    expiry: u64,
    decision: String,
    consumed: bool,
}

fn grant(conn: &Connection, nonce: Uuid) -> GuardResult<BoundGrant> {
    let (owner, action, expiry, decision, consumed): (u32, String, u64, String, bool) = conn
        .query_row(
            "SELECT owner, action, expires, decision, consumed FROM grants WHERE nonce=?1",
            [nonce.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    Ok(BoundGrant {
        owner,
        action: serde_json::from_str(&action)?,
        expiry,
        decision,
        consumed,
    })
}

impl Registry {
    pub fn issue_grant(
        &mut self,
        action: &Action,
        decision: &Governance,
        owner: u32,
        now: u64,
    ) -> GuardResult<Uuid> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = current(&txn, action)?;
        evidence::append(
            &txn,
            &row,
            EventFields {
                event_type: "GOVERNANCE_DECISION",
                observer: "controller",
                assurance: "HOST_REPORTED",
                request_id: Some(action.request_id),
                decision_id: Some(&decision.trace_id),
                result: if decision.ok {
                    "GOVERNED_COMMITTED"
                } else {
                    "DENIED"
                },
            },
        )?;
        if !decision.ok || decision.action_id.is_none() || decision.evidence_id.is_none() {
            txn.commit()?;
            return Err("controller denied or did not link evidence".into());
        }
        let nonce = Uuid::new_v4();
        let expiry = now
            .checked_add(GRANT_TTL_NS)
            .ok_or("grant clock overflow")?;
        txn.execute(
            "INSERT INTO grants (nonce, workload, request, owner, action, expires, decision)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
             WHERE NOT EXISTS (SELECT 1 FROM effects WHERE workload=?2 AND request=?3)",
            params![
                nonce.to_string(),
                action.workload_id.to_string(),
                action.request_id.to_string(),
                owner,
                serde_json::to_string(action)?,
                expiry,
                serde_json::to_string(decision)?
            ],
        )
        .and_then(|count| {
            if count == 1 {
                Ok(())
            } else {
                Err(rusqlite::Error::QueryReturnedNoRows)
            }
        })?;
        evidence::append(
            &txn,
            &row,
            EventFields {
                event_type: "PERMIT_ISSUED",
                observer: "guardd",
                assurance: "HOST_VERIFIED",
                request_id: Some(action.request_id),
                decision_id: Some(&decision.trace_id),
                result: "ISSUED",
            },
        )?;
        txn.commit()?;
        Ok(nonce)
    }

    pub fn redeem_grant(
        &mut self,
        nonce: Uuid,
        action: &Action,
        owner: u32,
        now: u64,
    ) -> GuardResult<()> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = current(&txn, action)?;
        let grant = grant(&txn, nonce)?;
        if grant.consumed || grant.owner != owner || grant.action != *action || now >= grant.expiry
        {
            return Err("permit is expired, consumed, or bound to a different effect".into());
        }
        let decision: Governance = serde_json::from_str(&grant.decision)?;
        txn.execute(
            "UPDATE grants SET consumed=1 WHERE nonce=?1",
            [nonce.to_string()],
        )?;
        txn.execute(
            "INSERT INTO effects VALUES (?1, ?2, ?3, ?4)",
            params![
                action.workload_id.to_string(),
                action.request_id.to_string(),
                serde_json::to_string(action)?,
                serde_json::to_string(&Outcome::Started)?,
            ],
        )?;
        evidence::append(
            &txn,
            &row,
            EventFields {
                event_type: "EFFECT_STARTED",
                observer: "guardd",
                assurance: "HOST_VERIFIED",
                request_id: Some(action.request_id),
                decision_id: Some(&decision.trace_id),
                result: "ADMITTED",
            },
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn authenticate_controller_session(&self, nonce: Uuid, session: Uuid) -> GuardResult<()> {
        let grant = grant(&self.conn, nonce)?;
        let decision: Governance = serde_json::from_str(&grant.decision)?;
        if decision.session != session {
            return Err("controller incarnation differs from the grant".into());
        }
        Ok(())
    }

    pub fn check_dispatch(&self, nonce: Uuid, owner: u32, now: u64) -> GuardResult<()> {
        let grant = grant(&self.conn, nonce)?;
        current(&self.conn, &grant.action)?;
        if !grant.consumed
            || grant.owner != owner
            || now >= grant.expiry
            || self.outcome(grant.action.workload_id, grant.action.request_id)?
                != Some(Outcome::Started)
        {
            return Err("transport dispatch is no longer admitted".into());
        }
        Ok(())
    }

    pub fn finish(&mut self, nonce: Uuid, owner: u32, outcome: Outcome) -> GuardResult<()> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let grant = grant(&txn, nonce)?;
        if !grant.consumed || grant.owner != owner || outcome == Outcome::Started {
            return Err("no matching admitted effect".into());
        }
        let action = grant.action;
        let row = workload(&txn, action.workload_id)?;
        let updated = txn.execute(
            "UPDATE effects SET outcome=?1 WHERE workload=?2 AND request=?3 AND outcome=?4",
            params![
                serde_json::to_string(&outcome)?,
                action.workload_id.to_string(),
                action.request_id.to_string(),
                serde_json::to_string(&Outcome::Started)?
            ],
        )?;
        if updated != 1 {
            return Err("effect already has a recorded outcome".into());
        }
        let decision: Governance = serde_json::from_str(&grant.decision)?;
        let (event_type, assurance, result) = match outcome {
            Outcome::Succeeded => ("EFFECT_SUCCEEDED", "EXTERNAL_ACK", "SUCCEEDED"),
            Outcome::Failed => ("EFFECT_FAILED", "HOST_REPORTED", "FAILED"),
            Outcome::OutcomeUnknown => ("EFFECT_UNKNOWN", "HOST_REPORTED", "OUTCOME_UNKNOWN"),
            Outcome::Started => unreachable!(),
        };
        evidence::append(
            &txn,
            &row,
            EventFields {
                event_type,
                observer: "gateway",
                assurance,
                request_id: Some(action.request_id),
                decision_id: Some(&decision.trace_id),
                result,
            },
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn outcome(&self, workload: Uuid, request: Uuid) -> GuardResult<Option<Outcome>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT outcome FROM effects WHERE workload=?1 AND request=?2",
                params![workload.to_string(), request.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(raw.as_deref().map(serde_json::from_str).transpose()?)
    }

    pub fn effect_status(&self, id: Uuid, request: Uuid) -> GuardResult<serde_json::Value> {
        let (action, outcome): (String, String) = self.conn.query_row(
            "SELECT action, outcome FROM effects WHERE workload=?1 AND request=?2",
            params![id.to_string(), request.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let action: Action = serde_json::from_str(&action)?;
        let outcome: Outcome = serde_json::from_str(&outcome)?;
        Ok(serde_json::json!({
            "outcome": outcome, "request_id": request, "idempotency_key": action.idempotency_key,
            "payload_sha256": action.payload_sha256, "target": action.target,
        }))
    }

    pub fn reconcile_receipt(
        &mut self,
        id: Uuid,
        request: Uuid,
        key: Uuid,
        payload_sha256: &str,
    ) -> GuardResult<()> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = workload(&txn, id)?;
        let raw: String = txn.query_row(
            "SELECT action FROM effects WHERE workload=?1 AND request=?2 AND outcome=?3",
            params![
                id.to_string(),
                request.to_string(),
                serde_json::to_string(&Outcome::OutcomeUnknown)?
            ],
            |row| row.get(0),
        )?;
        let action: Action = serde_json::from_str(&raw)?;
        if action.idempotency_key != key || action.payload_sha256 != payload_sha256 {
            return Err("collector receipt differs from the admitted effect".into());
        }
        txn.execute(
            "UPDATE effects SET outcome=?1 WHERE workload=?2 AND request=?3",
            params![
                serde_json::to_string(&Outcome::Succeeded)?,
                id.to_string(),
                request.to_string(),
            ],
        )?;
        evidence::append(
            &txn,
            &row,
            EventFields {
                event_type: "EFFECT_RECONCILED",
                observer: "operator",
                assurance: "EXTERNAL_RECEIPT_VERIFIED_BY_OPERATOR",
                request_id: Some(request),
                decision_id: None,
                result: "SUCCEEDED",
            },
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn recover_effects(&mut self) -> GuardResult<()> {
        self.recover_workload_effects(None)
    }

    pub fn recover_workload_effects(&mut self, id: Option<Uuid>) -> GuardResult<()> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scope = id.map(|item| item.to_string());
        let in_flight = {
            let mut query = txn.prepare(
                "SELECT effects.action, grants.decision FROM effects
                 LEFT JOIN grants ON grants.workload=effects.workload AND grants.request=effects.request
                 WHERE effects.outcome=?1 AND (?2 IS NULL OR effects.workload=?2)"
            )?;
            let entries = query.query_map(
                params![serde_json::to_string(&Outcome::Started)?, scope],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )?;
            entries.collect::<Result<Vec<_>, _>>()?
        };
        for (entry, linked) in in_flight {
            let action: Action = serde_json::from_str(&entry)?;
            let decision: Option<Governance> =
                linked.as_deref().map(serde_json::from_str).transpose()?;
            let row = workload(&txn, action.workload_id)?;
            txn.execute(
                "UPDATE effects SET outcome=?1 WHERE workload=?2 AND request=?3",
                params![
                    serde_json::to_string(&Outcome::OutcomeUnknown)?,
                    action.workload_id.to_string(),
                    action.request_id.to_string(),
                ],
            )?;
            evidence::append(
                &txn,
                &row,
                EventFields {
                    event_type: "EFFECT_UNKNOWN",
                    observer: "guardd_recovery",
                    assurance: "HOST_VERIFIED",
                    request_id: Some(action.request_id),
                    decision_id: decision.as_ref().map(|d| d.trace_id.as_str()),
                    result: "OUTCOME_UNKNOWN",
                },
            )?;
        }
        txn.execute(
            "DELETE FROM grants WHERE ?1 IS NULL OR workload=?1",
            [scope],
        )?;
        txn.commit()?;
        Ok(())
    }
}
