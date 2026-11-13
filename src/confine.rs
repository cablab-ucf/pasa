//! The sync process sees only `store/v/` and `net/`. Its parent has no socket.

use std::path::{Path, PathBuf};
use std::process::Command;

/// TLS roots named by the environment: public, so readable.
fn certs() -> Vec<PathBuf> {
    let vars = ["SSL_CERT_FILE", "SSL_CERT_DIR", "NIX_SSL_CERT_FILE"];
    let set = vars.iter().filter_map(std::env::var_os);
    set.flat_map(|v| std::env::split_paths(&v).collect::<Vec<_>>()).collect()
}

pub fn command(dir: &Path, exe: &Path, args: &[&str]) -> Command {
    #[cfg(target_os = "macos")]
    if let Some(profile) = profile(dir, exe) {
        let mut c = Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(profile).arg(exe).args(args);
        c.env("PASA_SANDBOX", "1").env("PASA_DIR", dir);
        return c;
    }
    let mut c = Command::new(exe);
    c.args(args).env("PASA_DIR", dir);
    c
}

/// Call before any socket. False on a kernel without Landlock. No signals,
/// abstract sockets or (ABI 9) unix sockets by path but under `unix`; on
/// Linux without `unix`, seccomp refuses new unix sockets on any kernel.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn confine(dir: &Path, unix: Option<&Path>) -> anyhow::Result<bool> {
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, Scope, path_beneath_rules,
    };
    let abi = ABI::V9;
    let own = [crate::versions(dir), dir.join("net")];
    own.iter().try_for_each(std::fs::create_dir_all)?;
    let system = [
        "/etc",
        "/usr",
        "/lib",
        "/lib64",
        "/nix/store",
        "/run/current-system",
        "/system",
        "/apex",
        "/vendor",
    ];
    let s = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .scope(Scope::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(&own, AccessFs::from_all(abi)))?
        .add_rules(path_beneath_rules(system, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(certs(), AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(unix, AccessFs::ResolveUnix))?
        .restrict_self()?;
    #[cfg(target_os = "linux")]
    if unix.is_none() {
        no_unix_sockets()?;
    }
    Ok(s.ruleset != RulesetStatus::NotEnforced)
}

/// seccomp: `socket(AF_UNIX)` and io_uring (which makes sockets past it)
/// fail, x32's numbers too; another architecture's calls kill.
#[cfg(target_os = "linux")]
fn no_unix_sockets() -> anyhow::Result<()> {
    use seccompiler::{SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp};
    use seccompiler::{SeccompCondition, SeccompFilter, SeccompRule};
    let unix = SeccompCondition::new(
        0,
        Len::Dword,
        SeccompCmpOp::Eq,
        libc::AF_UNIX as u64,
    )?;
    let socket =
        || Ok::<_, anyhow::Error>(vec![SeccompRule::new(vec![unix.clone()])?]);
    let x32 = if cfg!(target_arch = "x86_64") { 0x4000_0000 } else { 0 };
    let mut rules = std::collections::BTreeMap::new();
    for n in [0, x32] {
        rules.insert(libc::SYS_socket | n, socket()?);
        rules.insert(libc::SYS_io_uring_setup | n, vec![]);
    }
    let f = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        std::env::consts::ARCH.try_into()?,
    )?;
    let p: seccompiler::BpfProgram = f.try_into()?;
    seccompiler::apply_filter(&p)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn confine(_: &Path, _: Option<&Path>) -> anyhow::Result<bool> {
    Ok(std::env::var_os("PASA_SANDBOX").is_some())
}

/// Denies user file areas but `v/`, `net/`, the exe and certs; allows the rest.
#[cfg(target_os = "macos")]
fn profile(dir: &Path, exe: &Path) -> Option<String> {
    let at = |p: &Path| {
        let p = std::fs::canonicalize(p).ok()?;
        Some(format!("{:?}", p.to_str()?))
    };
    let own = [crate::versions(dir), dir.join("net")];
    own.iter().try_for_each(std::fs::create_dir_all).ok()?;
    let (v, net, exe) = (at(&own[0])?, at(&own[1])?, at(exe)?);
    let certs: String = certs()
        .iter()
        .filter_map(|c| at(c.as_path()))
        .map(|c| format!(" (subpath {c})"))
        .collect();
    Some(format!(
        "(version 1)(allow default)
         (deny file-read-data file-write*
           (require-all
             (require-any (subpath \"/Users\") (subpath \"/Volumes\")
               (subpath \"/private/var/folders\") (subpath \"/private/tmp\")
               (subpath \"/private/var/root\"))
             (require-not (require-any (subpath {v}) (subpath {net})
               (literal {exe}){certs}))))"
    ))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::fs;

    /// Runs in the confined child: confinement cannot be undone.
    fn probe(dir: &Path) {
        assert!(confine(dir, None).unwrap(), "not confined");
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::net::UnixDatagram;
            assert!(UnixDatagram::unbound().is_err(), "a unix socket");
            let parent = std::os::unix::process::parent_id() as i32;
            let parent = rustix::process::Pid::from_raw(parent).unwrap();
            let out = rustix::process::test_kill_process(parent);
            assert!(out.is_err(), "a signal out");
            assert!(std::net::UdpSocket::bind("127.0.0.1:0").is_ok(), "udp");
        }
        assert!(fs::read(crate::versions(dir).join("x")).is_ok(), "v/");
        assert!(fs::write(dir.join("net/peers"), b"").is_ok(), "net/");
        assert!(fs::read(dir.join("key")).is_err(), "the key file");
        assert!(fs::read(dir.join("dev")).is_err(), "dev");
        assert!(fs::write(dir.join("key"), b"").is_err(), "over the key");
        assert!(fs::read_dir(dir).is_err(), "the store's directory");
        let beside = dir.parent().unwrap().join("beside");
        assert!(fs::read(&beside).is_err(), "a file beside the store");
        if let Some(h) = std::env::home_dir() {
            assert!(fs::read_dir(h).is_err(), "home");
        }
    }

    #[test]
    fn the_network_side_sees_v_and_net_alone() {
        if let Some(d) = std::env::var_os("PASA_PROBE") {
            return probe(Path::new(&d));
        }
        #[cfg(target_os = "linux")]
        if let Some(s) = std::env::var_os("PASA_PROBE_UNIX") {
            // `listen`: pushir's socket, by path.
            let s = Path::new(&s);
            let d = s.parent().unwrap().join("store");
            assert!(confine(&d, s.parent()).unwrap(), "not confined");
            assert!(std::os::unix::net::UnixStream::connect(s).is_ok());
            return;
        }
        let d = crate::tests::dir("confine").join("store");
        fs::create_dir_all(crate::versions(&d)).unwrap();
        fs::write(crate::versions(&d).join("x"), b"age").unwrap();
        fs::write(d.join("key"), b"sealed").unwrap();
        fs::write(d.join("dev"), b"sealed").unwrap();
        fs::write(d.parent().unwrap().join("beside"), b"mine").unwrap();
        let exe = std::env::current_exe().unwrap();
        let name = "confine::tests::the_network_side_sees_v_and_net_alone";
        let mut c = command(&d, &exe, &["--exact", name, "--nocapture"]);
        let o = c.env("PASA_PROBE", &d).output().unwrap();
        let said = String::from_utf8_lossy(&o.stdout).to_string()
            + &String::from_utf8_lossy(&o.stderr);
        assert!(o.status.success(), "{said}");
        assert!(said.contains("1 passed"), "{said}");
        #[cfg(target_os = "linux")]
        {
            let s = d.parent().unwrap().join("sock");
            let _l = std::os::unix::net::UnixListener::bind(&s).unwrap();
            let mut c = command(&d, &exe, &["--exact", name, "--nocapture"]);
            let o = c.env("PASA_PROBE_UNIX", &s).output().unwrap();
            let said = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            assert!(o.status.success() && said.contains("1 passed"), "{said}");
        }
    }
}
