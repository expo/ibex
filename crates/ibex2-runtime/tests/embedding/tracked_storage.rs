//! @ref LLP 0068.001#6-rust-and-borrowed-jsi-integration — actual JSI dispatch and teardown.
use super::*;
use ibex2::boundary::HostError;
use ibex2::stdlib::fs_image::{
    CancelResult, CodecLimits, CompressedImage, ImageCodec, ImageRequest, WorkControl, WorkLimits,
    WorkState,
};
use std::sync::{mpsc, Mutex};
struct EchoCodec;
impl ImageCodec for EchoCodec {
    fn limits(&self) -> CodecLimits {
        CodecLimits {
            max_pixels: 1024,
            max_scratch_bytes: 1024,
        }
    }
    fn encode(
        &self,
        source: &[u8],
        _: ImageRequest,
        control: &WorkControl,
    ) -> Result<CompressedImage, HostError> {
        control.check()?;
        Ok(CompressedImage {
            bytes: source.to_vec(),
            width: 1,
            height: 1,
        })
    }
}
#[test]
fn borrowed_storage_uses_the_same_codec_and_retires_completion_on_delivery() {
    let consumer = Consumer::new("fs.read app:/\nfs.write app:/");
    consumer
        .context
        .set_image_codec(Arc::new(EchoCodec), WorkLimits::default())
        .unwrap();
    std::fs::write(consumer.directory.join("tmp/in"), b"encoded").unwrap();
    consumer.eval("globalThis.result=''; storage.fs.compressImage('app:/tmp/in','app:/data/out',16,64).then(x=>globalThis.result=x,e=>globalThis.result=String(e));").unwrap();
    assert_eq!(consumer.finish(), "1\t1\t7");
    assert_eq!(
        std::fs::read(consumer.directory.join("data/out")).unwrap(),
        b"encoded"
    );
    assert_eq!(consumer.context.image_work().outstanding_workers(), 0);
    assert_eq!(consumer.context.image_work().pending_completions(), 0);
}
struct BlockedCodec {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl ImageCodec for BlockedCodec {
    fn limits(&self) -> CodecLimits {
        CodecLimits {
            max_pixels: 1024,
            max_scratch_bytes: 1024,
        }
    }
    fn encode(
        &self,
        source: &[u8],
        _: ImageRequest,
        _: &WorkControl,
    ) -> Result<CompressedImage, HostError> {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        Ok(CompressedImage {
            bytes: source.to_vec(),
            width: 1,
            height: 1,
        })
    }
}
#[test]
fn borrowed_image_promises_correlate_owned_work_without_guest_ids() {
    let consumer = Consumer::new("fs.read app:/\nfs.write app:/");
    let (entered, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    consumer
        .context
        .set_image_codec(
            Arc::new(BlockedCodec {
                entered,
                release: Mutex::new(blocked),
            }),
            WorkLimits::default(),
        )
        .unwrap();
    std::fs::write(consumer.directory.join("tmp/in"), b"new").unwrap();
    std::fs::write(consumer.directory.join("data/first"), b"old-first").unwrap();
    std::fs::write(consumer.directory.join("data/second"), b"old-second").unwrap();
    consumer
        .eval(
            "globalThis.result='';
             globalThis.unrelated=storage.fs.readFile('app:/tmp/in');
             globalThis.firstImage=storage.fs.compressImage('app:/tmp/in','app:/data/first',16,64);
             globalThis.secondImage=storage.fs.compressImage('app:/tmp/in','app:/data/second',16,64);
             globalThis.derived=firstImage.then(()=>true,()=>false);
             globalThis.forged={task_id:2};
             globalThis.inherited=Object.create(firstImage);
             globalThis.primitive=42;
             Promise.all([
               firstImage.then(()=> 'unexpected commit',()=> 'abandoned'),
               secondImage.then(()=> 'committed',e=>String(e))
             ]).then(x=>globalThis.result=x.join('|'));",
        )
        .unwrap();
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    let task_id = |name: &CStr| unsafe {
        storage_consumer_image_task_id(consumer.handle, consumer.handle, name.as_ptr())
    };
    let first_id = task_id(c"firstImage");
    let second_id = task_id(c"secondImage");
    assert!(first_id > 1, "an unrelated async operation consumed an id");
    assert!(second_id > first_id);
    let first = consumer.context.image_work_handle(first_id).unwrap();
    let second = consumer.context.image_work_handle(second_id).unwrap();
    assert_ne!(first.id(), second.id());
    for name in [
        c"unrelated",
        c"derived",
        c"forged",
        c"inherited",
        c"primitive",
    ] {
        assert_eq!(task_id(name), 0, "unbranded value: {name:?}");
    }
    assert_eq!(
        consumer
            .eval(
                "typeof firstImage.task_id + '|' + Object.getOwnPropertySymbols(firstImage).length"
            )
            .unwrap(),
        "undefined|0"
    );
    assert_eq!(
        unsafe {
            storage_consumer_foreign_adapter_image_task_id(consumer.handle, c"firstImage".as_ptr())
        },
        0
    );
    let other = Consumer::new("");
    assert_eq!(
        unsafe {
            storage_consumer_image_task_id(other.handle, consumer.handle, c"firstImage".as_ptr())
        },
        0
    );
    assert_eq!(first.cancel(), CancelResult::Abandoned);
    assert_eq!(second.state(), WorkState::Running);
    release.send(()).unwrap();
    release.send(()).unwrap();
    assert_eq!(consumer.finish(), "abandoned|committed");
    assert_eq!(
        std::fs::read(consumer.directory.join("data/first")).unwrap(),
        b"old-first"
    );
    assert_eq!(
        std::fs::read(consumer.directory.join("data/second")).unwrap(),
        b"new"
    );
    assert_eq!(first.cancel(), CancelResult::Abandoned);
    assert!(matches!(second.cancel(), CancelResult::Settled(Ok(_))));
    for (name, id) in [(c"firstImage", first_id), (c"secondImage", second_id)] {
        assert_eq!(task_id(name), 0, "settled Promise is stale");
        assert!(consumer.context.image_work_handle(id).is_none());
    }
    assert_eq!(consumer.context.image_work().outstanding_workers(), 0);
    assert_eq!(consumer.context.image_work().pending_completions(), 0);
}
#[test]
fn borrowed_adapter_teardown_drops_guest_roots_while_native_worker_retires_later() {
    let root = std::env::temp_dir().join(format!(
        "ibex-jsi-image-{}",
        ibex2::stdlib::crypto::random_uuid().unwrap()
    ));
    for name in ["data", "cache", "tmp"] {
        std::fs::create_dir_all(root.join(name)).unwrap();
    }
    std::fs::write(root.join("tmp/in"), b"new").unwrap();
    std::fs::write(root.join("data/out"), b"old").unwrap();
    let context = Context::new(GrantSet::parse("fs.read app:/\nfs.write app:/").unwrap());
    context
        .set_app_directories(
            AppDirectories::new(root.join("data"), root.join("cache"), root.join("tmp")).unwrap(),
        )
        .unwrap();
    let (entered, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    context
        .set_image_codec(
            Arc::new(BlockedCodec {
                entered,
                release: Mutex::new(blocked),
            }),
            WorkLimits::default(),
        )
        .unwrap();
    let work = context.image_work().clone();
    let consumer = BareConsumer::from_context(Groups::PURE | Groups::STORAGE, context);
    consumer.harden(ibex2::bindings::HARDEN_BYTECODE).unwrap();
    consumer.eval_result("globalThis.imagePromise=fs.compressImage('app:/tmp/in','app:/data/out',16,64); imagePromise.then(()=>{ throw Error('must not deliver after teardown'); });").unwrap();
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    let id = unsafe {
        storage_consumer_image_task_id(consumer.handle, consumer.handle, c"imagePromise".as_ptr())
    };
    assert_ne!(id, 0);
    let handle = consumer
        .context
        .as_ref()
        .unwrap()
        .image_work_handle(id)
        .unwrap();
    assert_eq!(
        unsafe {
            storage_consumer_detached_image_task_id(consumer.handle, c"imagePromise".as_ptr())
        },
        0
    );
    drop(consumer);
    assert_eq!(handle.state(), WorkState::Abandoned);
    assert_eq!(work.outstanding_workers(), 1);
    release.send(()).unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while work.outstanding_workers() != 0 {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(std::fs::read(root.join("data/out")).unwrap(), b"old");
    assert_eq!(work.pending_completions(), 0);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn borrowed_document_denial_never_calls_provider_and_selected_file_roundtrips() {
    use ibex2::stdlib::fs::{DocumentLease, Documents};
    let consumer = Consumer::new("fs.read doc:/1\nfs.write doc:/1");
    let root = Arc::new(std::fs::File::open(&consumer.directory).unwrap());
    std::fs::write(consumer.directory.join("chosen"), b"document").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let provider: Arc<Documents> = Arc::new(move |_, _| {
        seen.fetch_add(1, Ordering::SeqCst);
        DocumentLease::selected_file(root.clone(), "chosen".into(), Arc::new(()))
    });
    consumer.context.set_documents(provider).unwrap();
    consumer.eval("globalThis.result=''; storage.fs.readFile('doc:/10/chosen').then(()=>result='bad',e=>result=String(e));").unwrap();
    assert!(consumer.finish().contains("denied"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    consumer.eval("globalThis.result=''; storage.fs.readFile('doc:/1/chosen').then(x=>result=String(x.byteLength),e=>result=String(e));").unwrap();
    assert_eq!(consumer.finish(), "8");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "loader")]
#[test]
fn owning_runtime_adopts_configured_storage_services_with_its_own_work_generation() {
    use ibex2::stdlib::fs::{DocumentLease, Documents, ResultLimits};
    use ibex2_runtime::engine::hermes::{DynamicCode, Hermes};
    let root = std::env::temp_dir().join(format!(
        "ibex-own-image-{}",
        ibex2::stdlib::crypto::random_uuid().unwrap()
    ));
    for name in ["data", "cache", "tmp"] {
        std::fs::create_dir_all(root.join(name)).unwrap();
    }
    std::fs::write(root.join("tmp/in"), b"encoded").unwrap();
    std::fs::write(root.join("chosen"), b"document").unwrap();
    let context = Context::new(GrantSet::none());
    context
        .set_app_directories(
            AppDirectories::new(root.join("data"), root.join("cache"), root.join("tmp")).unwrap(),
        )
        .unwrap();
    let (entered, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    context
        .set_image_codec(
            Arc::new(BlockedCodec {
                entered,
                release: Mutex::new(blocked),
            }),
            WorkLimits::default(),
        )
        .unwrap();
    let source_work = context.image_work().clone();
    context
        .set_storage_limits(ResultLimits { bytes: 1024 })
        .unwrap();
    let directory = Arc::new(std::fs::File::open(&root).unwrap());
    let provider: Arc<Documents> = Arc::new(move |_, _| {
        DocumentLease::selected_file(directory.clone(), "chosen".into(), Arc::new(()))
    });
    context.set_documents(provider).unwrap();
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    runtime
        .install_runtime(Groups::PURE | Groups::STORAGE, &context)
        .unwrap();
    runtime.harden().unwrap();
    std::fs::write(root.join("index.js"), "globalThis.result=''; fs.readFile('doc:/1/chosen').then(function(bytes) { return fs.compressImage('app:/tmp/in','app:/data/out',16,64).then(function(image) { result=bytes.byteLength+'|'+image; }); }).catch(function(error) { result=String(error); });").unwrap();
    runtime
        .set_loader(
            ibex2_runtime::loader::Root::Declared(root.clone()),
            ibex2_runtime::loader::ModuleGrants::parse(
                "[*]\nfs.read app:/\nfs.write app:/\nfs.read doc:/1\n",
            )
            .unwrap(),
        )
        .unwrap();
    runtime.run_entry("./index.js").unwrap();
    // First deliver the read settlement so its continuation dispatches image work.
    runtime.pump_until(1);
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(source_work.outstanding_workers(), 0);
    assert_eq!(source_work.pending_completions(), 0);
    drop(context); // An adopted owner must survive source Context retirement.
    release.send(()).unwrap();
    runtime.run_to_quiescence(Duration::from_secs(10));
    assert_eq!(runtime.eval("result").unwrap(), "8|1\t1\t7");
    assert_eq!(std::fs::read(root.join("data/out")).unwrap(), b"encoded");
    assert_eq!(source_work.outstanding_workers(), 0);
    assert_eq!(source_work.pending_completions(), 0);
    drop(runtime);
    std::fs::remove_dir_all(root).unwrap();
}
