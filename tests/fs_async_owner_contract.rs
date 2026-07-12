const POSIX_FS_RUNTIME: &str = include_str!("../src/engine/hermes_runtime_fs.cc");

#[test]
fn async_open_carries_the_scheduling_principal_into_fd_registration() {
    let register_start = POSIX_FS_RUNTIME.find("static void registerFd(").unwrap();
    let register_end = POSIX_FS_RUNTIME[register_start..]
        .find("\n}\n")
        .map(|offset| register_start + offset)
        .unwrap();
    let register_body = &POSIX_FS_RUNTIME[register_start..register_end];

    assert!(register_body.contains("uint64_t owner"));
    assert!(register_body.contains("FdEntry{owner,"));
    assert!(
        !register_body.contains("currentPrincipalId()"),
        "fd ownership must not be re-derived from delivery-time frames"
    );
    assert!(POSIX_FS_RUNTIME.contains("uint64_t openedOwner = 0;"));
    assert!(POSIX_FS_RUNTIME.contains("resultPtr->openedOwner = principal;"));
    assert!(
        POSIX_FS_RUNTIME.contains("static_cast<int>(resultPtr->number), resultPtr->openedOwner")
    );
}
