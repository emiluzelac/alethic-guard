//! Publish a content-addressed, read-only launch artifact in protected storage.

use crate::{GuardResult, digest_file};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use uuid::Uuid;

fn verify_snapshot(path: &Path, digest: &str) -> GuardResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o222 != 0
        || digest_file(path)? != digest
    {
        return Err("launch artifact failed integrity or access verification".into());
    }
    Ok(())
}

pub fn pin_file(mut source: File, destination: &Path, digest: &str) -> GuardResult<()> {
    match fs::symlink_metadata(destination) {
        Ok(_) => return verify_snapshot(destination, digest),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .ok_or("missing launch artifact directory")?;
    let stage = parent.join(format!(".staging-{}", Uuid::new_v4()));
    let mut staging = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)?;
    let result: GuardResult<()> = (|| {
        io::copy(&mut source, &mut staging)?;
        if digest_file(&stage)? != digest {
            return Err("approved artifact changed during staging".into());
        }
        staging.set_permissions(fs::Permissions::from_mode(0o444))?;
        staging.sync_all()?;
        match fs::hard_link(&stage, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_snapshot(destination, digest)?
            }
            Err(error) => return Err(error.into()),
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let cleanup = fs::remove_file(&stage);
    result?;
    cleanup?;
    Ok(())
}
