use crate::{
    GuardResult,
    auth::{PeerCredentials, process_start_time},
    broker::Binding,
    lifecycle::{Registry, Workload},
};
use rusqlite::{Connection, params};

pub fn initialize(conn: &Connection) -> GuardResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS gateway_processes (
             slot INTEGER PRIMARY KEY, pid INTEGER NOT NULL, start_time INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

impl Registry {
    pub fn bind_gateway_process(&mut self, row: &Workload, pid: u32) -> GuardResult<u64> {
        let bindings = self.bindings(Some(row.enrollment.id))?;
        let mut active = bindings
            .into_iter()
            .filter(|binding| binding.active && binding.generation == row.generation);
        let binding = active
            .next()
            .ok_or("gateway has no active runtime binding")?;
        if active.next().is_some() {
            return Err("gateway has multiple active runtime bindings".into());
        }
        let start_time = process_start_time(pid)?;
        self.conn.execute(
            "INSERT INTO gateway_processes VALUES (?1, ?2, ?3)",
            params![binding.slot, pid, start_time],
        )?;
        Ok(start_time)
    }

    pub fn has_active_gateway_process(
        &self,
        id: uuid::Uuid,
        generation: u64,
        pid: u32,
        start_time: u64,
    ) -> GuardResult<bool> {
        let count: u64 = self.conn.query_row(
            "SELECT count(*) FROM gateway_bindings JOIN gateway_processes USING (slot)
             WHERE workload=?1 AND generation=?2 AND pid=?3 AND start_time=?4 AND active=1 AND retired=0",
            params![id.to_string(), generation, pid, start_time],
            |row| row.get(0),
        )?;
        Ok(count != 0)
    }

    pub fn require_gateway_process(
        &self,
        binding: Binding,
        peer: PeerCredentials,
    ) -> GuardResult<()> {
        let (pid, start_time): (u32, u64) = self.conn.query_row(
            "SELECT pid, start_time FROM gateway_processes WHERE slot=?1",
            [binding.slot],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if peer.uid != binding.uid() || peer.pid != pid || process_start_time(pid)? != start_time {
            return Err("gateway process does not match the active runtime binding".into());
        }
        Ok(())
    }
}
