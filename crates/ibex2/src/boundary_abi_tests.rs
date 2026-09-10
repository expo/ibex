use super::*;
use std::sync::{mpsc, Arc};

#[test]
#[cfg(unix)]
fn shutdown_quiesces_a_write_already_inside_the_filesystem() {
    use std::{
        io::Read,
        os::unix::fs::OpenOptionsExt,
        time::{Duration, Instant},
    };
    let path = std::env::temp_dir().join(format!("ibex-fs-active-{}", std::process::id()));
    let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    let state = Arc::new(crate::task::RuntimeState::new(
        crate::transport::default_transport(),
    ));
    let grants = GrantSet::parse(&format!("fs.write {}", path.display())).unwrap();
    let worker_state = state.clone();
    let worker_path = path.to_str().unwrap().to_owned();
    let writer = std::thread::spawn(move || {
        run_async(
            AsyncOp::FsWriteFile,
            &[
                HostValue::Str(worker_path),
                HostValue::Bytes(vec![7; 1_048_576]),
            ],
            &worker_state,
            &grants,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = 0;
    // Seeing the first byte proves the real write entered its OS operation.
    while received == 0 {
        received = reader.read(&mut [0; 1]).unwrap_or_else(|e| {
            assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
            0
        });
        assert!(Instant::now() < deadline, "FIFO writer did not start");
        std::thread::yield_now();
    }
    let (finished, done) = mpsc::channel();
    let shutdown = std::thread::spawn(move || {
        state.shutdown();
        finished.send(()).unwrap();
    });
    assert!(
        done.recv_timeout(Duration::from_millis(50)).is_err(),
        "shutdown returned while an old write could still mutate"
    );
    let mut buffer = [0; 65536];
    while received < 1_048_576 {
        received += reader.read(&mut buffer).unwrap_or_else(|e| {
            assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
            0
        });
        assert!(Instant::now() < deadline, "FIFO writer failed to finish");
        std::thread::yield_now();
    }
    writer.join().unwrap().unwrap();
    done.recv_timeout(Duration::from_secs(5)).unwrap();
    shutdown.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn queued_old_atomic_write_cannot_overwrite_a_replacement_session() {
    let directory = std::env::temp_dir().join(format!("ibex-fs-shutdown-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("note").to_str().unwrap().to_owned();
    let grants = GrantSet::parse(&format!("fs.write {}", directory.display())).unwrap();
    let old = Arc::new(crate::task::RuntimeState::new(
        crate::transport::default_transport(),
    ));
    let (resume, paused) = mpsc::channel();
    let state = old.clone();
    let old_grants = grants.clone();
    let old_path = path.clone();
    // Control scheduling at the same seam a queued pool worker enters.
    let worker = std::thread::spawn(move || {
        paused.recv().unwrap();
        run_async(
            AsyncOp::FsAtomicWriteFile,
            &[
                HostValue::Str(old_path),
                HostValue::Bytes(b"cancel".to_vec()),
            ],
            &state,
            &old_grants,
        )
    });
    old.shutdown();
    let new = crate::task::RuntimeState::new(crate::transport::default_transport());
    run_async(
        AsyncOp::FsAtomicWriteFile,
        &[
            HostValue::Str(path.clone()),
            HostValue::Bytes(b"again".to_vec()),
        ],
        &new,
        &grants,
    )
    .unwrap();
    resume.send(()).unwrap();
    let result = worker.join().unwrap();
    let bytes = std::fs::read(path).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(result.is_err(), "shutdown admitted the queued old write");
    assert_eq!(bytes, b"again");
}
