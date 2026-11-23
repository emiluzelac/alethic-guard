//! Publish a content-addressed, read-only launch artifact in protected storage.

use crate::{GuardResult, digest_file};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
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
        staging.set_permissions(fs::Permissions::from_mode(0o400))?;
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

/// Give only the owner and the designated emulator account access. The
/// Linux POSIX ACL xattr layout is versioned in linux/posix_acl_xattr.h.
pub fn restrict_to_emulator(path: &Path, uid: u32) -> GuardResult<()> {
    if uid == 0 || uid == u32::MAX {
        return Err("invalid emulator service identity".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    let (owner, emulator) = if metadata.is_dir() {
        (7u16, 1u16)
    } else if metadata.is_file() {
        (4u16, 4u16)
    } else {
        return Err("launch ACL requires a regular file or directory".into());
    };
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, identity) in [
        (0x01u16, owner, u32::MAX),
        (0x02, emulator, uid),
        (0x04, 0, u32::MAX),
        (0x10, emulator, u32::MAX),
        (0x20, 0, u32::MAX),
    ] {
        acl.extend(tag.to_le_bytes());
        acl.extend(permissions.to_le_bytes());
        acl.extend(identity.to_le_bytes());
    }
    let name = c"system.posix_acl_access";
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut actual = vec![0; acl.len()];
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != acl.len() || actual != acl {
        return Err("launch ACL readback differs from the required access".into());
    }
    Ok(())
}
