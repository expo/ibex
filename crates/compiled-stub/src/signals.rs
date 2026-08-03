//! Process-lifetime POSIX signal mediation for standalone applications.

use anyhow::{bail, Context, Result};

const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// Block the standalone lifecycle signals before the runtime creates any
/// worker threads, then dedicate one inherited-blocked thread to `sigwait`.
/// This keeps termination independent of a wedged engine while still giving
/// the console broker one bounded opportunity to publish accepted output.
/// @ref LLP 0025#8-exit-and-lifecycle
pub fn install() -> Result<()> {
    let mut wait_set = empty_signal_set()?;
    for signal in SIGNALS {
        if unsafe { libc::sigaddset(&mut wait_set, signal) } != 0 {
            bail!("cannot add signal {signal} to the compiled wait set");
        }
    }

    let mut previous_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mask_status =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &wait_set, &mut previous_mask) };
    if mask_status != 0 {
        bail!("cannot block compiled lifecycle signals ({mask_status})");
    }

    let mut previous_actions = Vec::with_capacity(SIGNALS.len());
    for signal in SIGNALS {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            restore(&previous_mask, &previous_actions);
            bail!("cannot initialize disposition for signal {signal}");
        }
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
            restore(&previous_mask, &previous_actions);
            bail!("cannot install disposition for signal {signal}");
        }
        previous_actions.push((signal, previous));
    }

    if let Err(error) = std::thread::Builder::new()
        .name("ibex-compiled-signals".into())
        .spawn(signal_wait_loop)
    {
        restore(&previous_mask, &previous_actions);
        return Err(error).context("cannot start compiled signal coordinator");
    }
    Ok(())
}

fn signal_wait_loop() {
    let Ok(mut wait_set) = empty_signal_set() else {
        fatal_coordinator_failure();
    };
    for signal in SIGNALS {
        if unsafe { libc::sigaddset(&mut wait_set, signal) } != 0 {
            fatal_coordinator_failure();
        }
    }

    let mut signal = 0;
    let status = unsafe { libc::sigwait(&wait_set, &mut signal) };
    if status != 0 || !SIGNALS.contains(&signal) {
        fatal_coordinator_failure();
    }

    ibex_runtime::host::abi::ex_host_console_flush(500);
    unsafe { libc::_exit(128 + signal) }
}

fn empty_signal_set() -> Result<libc::sigset_t> {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigemptyset(&mut set) } != 0 {
        bail!("cannot initialize compiled signal set");
    }
    Ok(set)
}

fn restore(previous_mask: &libc::sigset_t, previous_actions: &[(libc::c_int, libc::sigaction)]) {
    for (signal, action) in previous_actions.iter().rev() {
        unsafe {
            libc::sigaction(*signal, action, std::ptr::null_mut());
        }
    }
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, previous_mask, std::ptr::null_mut());
    }
}

fn fatal_coordinator_failure() -> ! {
    ibex_runtime::host::abi::ex_host_console_flush(500);
    unsafe { libc::_exit(70) }
}
