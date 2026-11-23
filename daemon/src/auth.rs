use std::{
    io, mem,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

#[derive(Clone, Copy)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
}

pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut creds: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SO_PEERCRED returns the kernel's credential snapshot from connect().
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut creds as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(mem::size_of::<libc::ucred>()) {
        return Err(io::Error::other("unexpected peer credentials"));
    }
    let pid = u32::try_from(creds.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| io::Error::other("peer process ID unavailable"))?;
    Ok(PeerCredentials {
        pid,
        uid: creds.uid,
    })
}

pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    Ok(peer_credentials(stream)?.uid)
}

pub fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The parenthesized command may itself contain spaces or ')'.
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::other("process start time unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_peer_credentials_include_kernel_process_identity() {
        let (host, _) = UnixStream::pair().unwrap();
        let credentials = peer_credentials(&host).unwrap();
        assert_eq!(credentials.pid, std::process::id());
        assert_eq!(credentials.uid, unsafe { libc::geteuid() });
    }

    #[test]
    fn process_start_time_matches_the_registered_incarnation() {
        let pid = std::process::id();
        let start_time = process_start_time(pid).unwrap();
        assert_eq!(process_start_time(pid).unwrap(), start_time);
        assert!(process_start_time(0).is_err());
    }
}
