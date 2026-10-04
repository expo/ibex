#[allow(dead_code)]
#[path = "../build_support.rs"]
mod build_support;

use build_support::{
    acquire_bundle, download_options_from_env, parse_pin_sha256, pin_for_target,
    verify_and_extract_archive, BundlePin, DownloadOptions, RELEASE_TAG,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

const ASSET: &str = "hermes-vanilla-test-target.tar.gz";
const CACHE_RECORD: &str = ".hermes-lean-sys-archive-sha256";

#[test]
fn target_to_asset_mapping_includes_ios_simulator_aliases() {
    assert_eq!(
        pin_for_target("aarch64-apple-ios-sim")
            .expect("arm simulator pin")
            .asset,
        "hermes-vanilla-universal-apple-ios-simulator.tar.gz"
    );
    assert_eq!(
        pin_for_target("x86_64-apple-ios")
            .expect("x64 simulator pin")
            .asset,
        "hermes-vanilla-universal-apple-ios-simulator.tar.gz"
    );
    let error = pin_for_target("riscv64-unknown-linux-gnu").expect_err("unsupported target");
    assert!(error.contains("HERMES_LEAN_SYS_DIR"), "{error}");
}

#[test]
fn pin_table_digest_parser_accepts_only_sha256_hex() {
    assert_eq!(
        parse_pin_sha256(&"A".repeat(64)).expect("valid SHA-256"),
        "a".repeat(64)
    );
    assert!(parse_pin_sha256("abc").is_err());
    assert!(parse_pin_sha256(&"g".repeat(64)).is_err());
    let placeholder = parse_pin_sha256("TODO_L1D_SHA256_TEST").expect_err("placeholder");
    assert!(
        placeholder.contains("awaiting publication"),
        "{placeholder}"
    );
}

#[test]
fn digest_mismatch_is_refused_before_extraction() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let archive = temporary.path().join("bundle.tar.gz");
    write_archive(&archive, &[ArchiveEntry::File("sentinel", b"contents")]);
    let destination = temporary.path().join("install");

    let error = verify_and_extract_archive(&archive, &"0".repeat(64), &destination)
        .expect_err("digest mismatch");
    assert!(error.contains("nothing was extracted"), "{error}");
    assert!(!destination.exists());
}

#[test]
fn traversal_and_link_entries_are_refused() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let traversal = temporary.path().join("traversal.tar.gz");
    write_archive(&traversal, &[ArchiveEntry::File("safe-name", b"no")]);
    replace_first_tar_path(&traversal, "../escape");
    let traversal_digest = sha256_file(&traversal);
    let error = verify_and_extract_archive(
        &traversal,
        &traversal_digest,
        &temporary.path().join("traversal-out"),
    )
    .expect_err("traversal must fail");
    assert!(
        error.contains("unsafe") || error.contains("path"),
        "{error}"
    );
    assert!(!temporary.path().join("escape").exists());

    let absolute = temporary.path().join("absolute.tar.gz");
    write_archive(&absolute, &[ArchiveEntry::File("safe-name", b"no")]);
    replace_first_tar_path(&absolute, "/absolute-escape");
    let absolute_digest = sha256_file(&absolute);
    let error = verify_and_extract_archive(
        &absolute,
        &absolute_digest,
        &temporary.path().join("absolute-out"),
    )
    .expect_err("absolute path must fail");
    assert!(
        error.contains("unsafe") || error.contains("path"),
        "{error}"
    );

    let links = temporary.path().join("links.tar.gz");
    write_archive(&links, &[ArchiveEntry::Symlink("link", "target")]);
    let link_digest = sha256_file(&links);
    let error =
        verify_and_extract_archive(&links, &link_digest, &temporary.path().join("link-out"))
            .expect_err("link must fail");
    assert!(
        error.contains("links and special files are forbidden"),
        "{error}"
    );
    assert!(!temporary.path().join("link-out").exists());
}

#[test]
fn offline_empty_cache_fails_with_recovery_instructions() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let digest = leak("1".repeat(64));
    let pin = BundlePin {
        target: "test-target",
        asset: ASSET,
        sha256: digest,
    };
    let options = DownloadOptions {
        cache_root: temporary.path().join("cache"),
        release_base_url: "http://127.0.0.1:1".to_owned(),
        offline: true,
    };

    let error = acquire_bundle(&pin, &options).expect_err("empty offline cache");
    assert!(error.contains("offline mode is enabled"), "{error}");
    assert!(error.contains("HERMES_LEAN_SYS_DIR"), "{error}");
}

#[test]
fn cache_is_reused_only_with_a_matching_digest_record() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let digest = "2".repeat(64);
    let entry = temporary
        .path()
        .join("cache")
        .join(RELEASE_TAG)
        .join(&digest);
    fs::create_dir_all(&entry).expect("cache entry");
    fs::write(entry.join("sentinel"), b"warm").expect("sentinel");
    fs::write(entry.join(CACHE_RECORD), format!("{digest}\n")).expect("digest record");
    let pin = BundlePin {
        target: "test-target",
        asset: ASSET,
        sha256: leak(digest.clone()),
    };
    let options = DownloadOptions {
        cache_root: temporary.path().join("cache"),
        release_base_url: "http://127.0.0.1:1".to_owned(),
        offline: true,
    };

    let reused = acquire_bundle(&pin, &options).expect("matching cache entry");
    assert_eq!(reused, entry);
    fs::write(reused.join(CACHE_RECORD), format!("{}\n", "3".repeat(64))).expect("replace record");
    let error = acquire_bundle(&pin, &options).expect_err("mismatched cache record");
    assert!(error.contains("does not match pinned digest"), "{error}");
}

#[test]
fn local_http_mirror_bundle_is_verified_and_cached() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let archive = temporary.path().join(ASSET);
    write_archive(
        &archive,
        &[
            ArchiveEntry::File("include/hermes/hermes.h", b"header"),
            ArchiveEntry::File("lib/libhermesvm_a.a", b"engine"),
            ArchiveEntry::File("bin/hermesc", b"compiler"),
        ],
    );
    let bytes = fs::read(&archive).expect("archive bytes");
    let digest = sha256_bytes(&bytes);
    let listener = TcpListener::bind("127.0.0.1:0").expect("local listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("mirror request");
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).expect("read request");
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(
            request.starts_with(&format!("GET /{RELEASE_TAG}/{ASSET} ")),
            "{request}"
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .expect("response header");
        stream.write_all(&bytes).expect("response body");
    });

    let _mirror = EnvGuard::set("HERMES_LEAN_SYS_MIRROR", &format!("http://{address}"));
    let mut options = download_options_from_env().expect("environment options");
    options.cache_root = temporary.path().join("cache");
    options.offline = false;
    let pin = BundlePin {
        target: "test-target",
        asset: ASSET,
        sha256: leak(digest.clone()),
    };
    let installed = acquire_bundle(&pin, &options).expect("downloaded bundle");
    server.join().expect("mirror server");

    assert_eq!(
        fs::read(installed.join("lib/libhermesvm_a.a")).expect("engine"),
        b"engine"
    );
    assert_eq!(
        fs::read_to_string(installed.join(CACHE_RECORD))
            .expect("digest record")
            .trim(),
        digest
    );
}

enum ArchiveEntry<'a> {
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
}

fn write_archive(path: &Path, entries: &[ArchiveEntry<'_>]) {
    let file = fs::File::create(path).expect("archive file");
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for entry in entries {
        match entry {
            ArchiveEntry::File(name, contents) => {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o644);
                header.set_size(contents.len() as u64);
                header.set_cksum();
                archive
                    .append_data(&mut header, name, *contents)
                    .expect("regular entry");
            }
            ArchiveEntry::Symlink(name, target) => {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_mode(0o777);
                header.set_size(0);
                header.set_link_name(target).expect("link target");
                header.set_cksum();
                archive
                    .append_data(&mut header, name, &[][..])
                    .expect("link entry");
            }
        }
    }
    let encoder = archive.into_inner().expect("finish tar");
    encoder.finish().expect("finish gzip");
}

fn replace_first_tar_path(path: &Path, replacement: &str) {
    let compressed = fs::read(path).expect("compressed archive");
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut tar_bytes = Vec::new();
    decoder.read_to_end(&mut tar_bytes).expect("decode archive");
    assert!(replacement.len() < 100);
    tar_bytes[..100].fill(0);
    tar_bytes[..replacement.len()].copy_from_slice(replacement.as_bytes());
    tar_bytes[148..156].fill(b' ');
    let checksum: u32 = tar_bytes[..512].iter().map(|byte| u32::from(*byte)).sum();
    let field = format!("{checksum:06o}\0 ");
    tar_bytes[148..156].copy_from_slice(field.as_bytes());
    let file = fs::File::create(path).expect("rewritten archive");
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder.write_all(&tar_bytes).expect("rewritten tar");
    encoder.finish().expect("finish rewritten gzip");
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&fs::read(path).expect("digest input"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn leak(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

struct EnvGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = env::var_os(name);
        env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            env::set_var(self.name, previous);
        } else {
            env::remove_var(self.name);
        }
    }
}
