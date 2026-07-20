const POSIX_FS_RUNTIME: &str = include_str!("../src/engine/hermes_runtime_fs.cc");

#[test]
fn async_open_carries_the_scheduling_principal_into_fd_registration() {
    // `include_str!` preserves the checkout's CRLF bytes on Windows.
    let posix_fs_runtime = POSIX_FS_RUNTIME.replace("\r\n", "\n");
    let register_start = posix_fs_runtime.find("static void registerFd(").unwrap();
    let register_end = posix_fs_runtime[register_start..]
        .find("\n}\n")
        .map(|offset| register_start + offset)
        .unwrap();
    let register_body = &posix_fs_runtime[register_start..register_end];

    assert!(register_body.contains("uint64_t owner"));
    assert!(register_body.contains("FdEntry{exactCurrentRuntimeNonce(), owner,"));
    assert!(
        !register_body.contains("currentPrincipalId()"),
        "fd ownership must not be re-derived from delivery-time frames"
    );
    assert!(posix_fs_runtime.contains("uint64_t openedOwner = 0;"));
    assert!(posix_fs_runtime.contains("resultPtr->openedOwner = principal;"));
    assert!(posix_fs_runtime.contains(
        "resultPtr->openedCanRead, resultPtr->openedCanWrite,\n                              resultPtr->openedOwner,"
    ));
}
