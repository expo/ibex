//! Host ABI implementation (CLI layer)
//!
//! Re-exports core types from the Ibex library, including the shared HTTP
//! server (compiled there behind the `host-http-server` feature).

// The HTTP server lives in the library so app hosts and the binary link the
// same implementation. @ref LLP 0010#binary-implementation
#[cfg(feature = "host-http-server")]
pub use exact_runtime::host::http_server;

#[cfg(not(feature = "host-http-server"))]
pub mod http_server {
    extern "C" {
        #[link_name = "ex_host_http_has_referenced"]
        fn ex_host_http_has_referenced_ffi() -> i32;
        #[link_name = "ex_host_http_has_pending_requests"]
        fn ex_host_http_has_pending_requests_ffi() -> i32;
    }

    pub fn ex_host_http_has_referenced() -> i32 {
        unsafe { ex_host_http_has_referenced_ffi() }
    }

    pub fn ex_host_http_has_pending_requests() -> i32 {
        unsafe { ex_host_http_has_pending_requests_ffi() }
    }

    pub fn close_all_http_servers(_force: i32) -> usize {
        0
    }

    #[allow(dead_code)]
    pub fn is_server_listening(_server_id: u32) -> bool {
        false
    }
}

// Re-export everything from the shared runtime
#[allow(unused_imports)]
pub use exact_runtime::host::{abi, capability, policy, process, Host, HostConfig, SecurityMode};
