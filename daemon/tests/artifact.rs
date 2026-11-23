use alethic_guardd::{artifact::pin_file, digest_file};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn pinned_launch_bytes_survive_a_source_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    let artifact = dir.path().join("pinned.raw");
    fs::write(&source, b"approved").unwrap();
    let digest = digest_file(&source).unwrap();

    pin_file(fs::File::open(&source).unwrap(), &artifact, &digest).unwrap();
    fs::write(&source, b"changed").unwrap();

    assert_eq!(fs::read(&artifact).unwrap(), b"approved");
    assert_eq!(
        artifact.metadata().unwrap().permissions().mode() & 0o777,
        0o444
    );
    assert!(pin_file(fs::File::open(&source).unwrap(), &artifact, &digest).is_ok());
}

#[test]
fn changed_input_and_existing_wrong_snapshot_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    let artifact = dir.path().join("pinned.raw");
    fs::write(&source, b"approved").unwrap();
    let digest = digest_file(&source).unwrap();
    fs::write(&source, b"changed").unwrap();

    assert!(pin_file(fs::File::open(&source).unwrap(), &artifact, &digest).is_err());
    assert!(!artifact.exists());

    fs::write(&artifact, b"old wrong input").unwrap();
    assert!(pin_file(fs::File::open(&source).unwrap(), &artifact, &digest).is_err());
    assert_eq!(fs::read(&artifact).unwrap(), b"old wrong input");
}
