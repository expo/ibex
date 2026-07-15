//! Safe Rust ownership over the native Hermes module-runner capabilities.
//!
//! The only factory compilation entry accepts a verified artifact capability;
//! raw/deserialized artifacts cannot reach the C++ compiler through this API.
//! @ref LLP 0027#canonical-encoding-and-validation

use std::ffi::{c_char, c_void, CStr};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use anyhow::{anyhow, bail, Result};

use crate::module_loader::artifact::VerifiedModuleArtifactV1;
use crate::module_loader::identity::SourceId;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeModuleHandle {
    opaque: [u64; 3],
}

unsafe extern "C" {
    fn ex_hermes_module_compile_factory(
        runtime: *mut c_void,
        runtime_nonce: u64,
        principal_id: u32,
        graph_generation: u64,
        compartment_identity: *const u8,
        compartment_identity_len: usize,
        semantic_digest: *const u8,
        semantic_digest_len: usize,
        source_id: *const u8,
        source_id_len: usize,
        factory_source: *const u8,
        factory_source_len: usize,
        source_label: *const u8,
        source_label_len: usize,
        out_factory: *mut NativeModuleHandle,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_module_release_handle(
        runtime: *mut c_void,
        runtime_nonce: u64,
        handle: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_graph_context_create(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
        requesting_source_id: *const u8,
        requesting_source_id_len: usize,
        effect_owner: u32,
        schedule_owner: u32,
        constrained_principals: *const u32,
        constrained_principals_len: usize,
        out_context: *mut NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_graph_context_retain(
        runtime: *mut c_void,
        runtime_nonce: u64,
        context: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_module_create_record(
        runtime: *mut c_void,
        runtime_nonce: u64,
        factory: NativeModuleHandle,
        context: NativeModuleHandle,
        source_id: *const u8,
        source_id_len: usize,
        out_record: *mut NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut c_char);
}

/// Borrowed owner-thread access to one live Hermes runtime generation.
///
/// Construction is unsafe because the embedding wrapper must prove the pointer
/// and nonce were captured together while live and that the borrow does not
/// outlive the runtime. The type is deliberately `!Send`/`!Sync`.
pub struct NativeModuleRuntime<'runtime> {
    raw: NonNull<c_void>,
    nonce: u64,
    _runtime: PhantomData<&'runtime mut c_void>,
    _owner_thread: PhantomData<Rc<()>>,
}

impl<'runtime> NativeModuleRuntime<'runtime> {
    /// # Safety
    ///
    /// `raw` must name the live runtime generation identified by `nonce`, the
    /// caller must be its owner thread, and the returned borrow must not outlive
    /// that runtime. Native validation independently refuses violations.
    pub unsafe fn from_raw(raw: NonNull<c_void>, nonce: u64) -> Result<Self> {
        if nonce == 0 {
            bail!("module runtime nonce must be nonzero");
        }
        Ok(Self {
            raw,
            nonce,
            _runtime: PhantomData,
            _owner_thread: PhantomData,
        })
    }

    /// Compile one inline factory after ModuleArtifact admission. Principal and
    /// compartment are graph-owned inputs; neither is read from artifact JS.
    pub fn compile_verified_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        if graph_generation == 0 {
            bail!("module graph generation must be nonzero");
        }
        let artifact = verified.artifact();
        let source = verified.inline_factory_source().ok_or_else(|| {
            anyhow!("prepared carrier factory bytes must be loaded and verified before compilation")
        })?;
        let compartment = compartment_identity.unwrap_or("");
        let digest = artifact.semantic_digest.as_str();
        let source_id = artifact.semantics.source_id.0.encode()?;
        let mut handle = NativeModuleHandle::default();
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_compile_factory(
                self.raw.as_ptr(),
                self.nonce,
                principal_id,
                graph_generation,
                compartment.as_ptr(),
                compartment.len(),
                digest.as_ptr(),
                digest.len(),
                source_id.as_ptr(),
                source_id.len(),
                source.as_ptr(),
                source.len(),
                source_label.as_ptr(),
                source_label.len(),
                &mut handle,
                &mut error,
            )
        };
        if status != 0 {
            let detail = take_error(error);
            bail!("native module factory compile refused ({status}): {detail}");
        }
        if !error.is_null() {
            unsafe { ex_hermes_free_string(error) };
        }
        Ok(CompiledModuleFactory {
            runtime: self,
            handle: Some(handle),
        })
    }

    pub fn create_graph_context(
        &'runtime self,
        context: GraphEvaluationContext,
    ) -> Result<NativeGraphContext<'runtime>> {
        context.validate()?;
        let source_id = context.requesting_record.encode()?;
        let mut handle = NativeModuleHandle::default();
        let principals = context.constrained_principals;
        let status = unsafe {
            ex_hermes_graph_context_create(
                self.raw.as_ptr(),
                self.nonce,
                context.graph_generation,
                source_id.as_ptr(),
                source_id.len(),
                context.effect_owner,
                context.schedule_owner,
                principals.as_ptr(),
                principals.len(),
                &mut handle,
            )
        };
        if status != 0 {
            bail!("native graph-context creation refused ({status})");
        }
        Ok(NativeGraphContext {
            runtime: self,
            handle: Some(handle),
        })
    }
}

/// Complete context carried by graph operations and asynchronous continuations.
/// Principal IDs are runtime-local projections; the requesting SourceId remains
/// stable and authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEvaluationContext {
    pub requesting_record: SourceId,
    pub effect_owner: u32,
    pub schedule_owner: u32,
    pub constrained_principals: Vec<u32>,
    pub graph_generation: u64,
}

impl GraphEvaluationContext {
    pub fn new(
        requesting_record: SourceId,
        effect_owner: u32,
        schedule_owner: u32,
        constrained_principals: impl IntoIterator<Item = u32>,
        graph_generation: u64,
    ) -> Result<Self> {
        let mut constrained_principals: Vec<_> = constrained_principals.into_iter().collect();
        constrained_principals.sort_unstable();
        constrained_principals.dedup();
        let value = Self {
            requesting_record,
            effect_owner,
            schedule_owner,
            constrained_principals,
            graph_generation,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.graph_generation == 0 {
            bail!("graph evaluation context generation must be nonzero");
        }
        if self.constrained_principals.len() > 256 {
            bail!("graph evaluation context exceeds 256 constrained principals");
        }
        if self
            .constrained_principals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            bail!("graph evaluation constrained principals must be sorted and unique");
        }
        Ok(())
    }
}

/// Owner-thread, runtime-generation-scoped callable factory capability.
pub struct CompiledModuleFactory<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
}

impl<'runtime> CompiledModuleFactory<'runtime> {
    pub fn create_record(
        &self,
        context: &NativeGraphContext<'runtime>,
        source_id: &SourceId,
    ) -> Result<NativeModuleRecord<'runtime>> {
        if !std::ptr::eq(self.runtime, context.runtime) {
            bail!("factory and graph context belong to different runtime borrows");
        }
        let factory = self
            .handle
            .ok_or_else(|| anyhow!("module factory capability was released"))?;
        let context_handle = context
            .handle
            .ok_or_else(|| anyhow!("graph context capability was released"))?;
        let source_id = source_id.encode()?;
        let mut record = NativeModuleHandle::default();
        let status = unsafe {
            ex_hermes_module_create_record(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                factory,
                context_handle,
                source_id.as_ptr(),
                source_id.len(),
                &mut record,
            )
        };
        if status != 0 {
            bail!("native ModuleRecord creation refused ({status})");
        }
        Ok(NativeModuleRecord {
            runtime: self.runtime,
            handle: Some(record),
        })
    }
}

pub struct NativeGraphContext<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
}

impl Clone for NativeGraphContext<'_> {
    fn clone(&self) -> Self {
        let handle = self.handle.expect("cannot clone a released graph context");
        let status = unsafe {
            ex_hermes_graph_context_retain(self.runtime.raw.as_ptr(), self.runtime.nonce, handle)
        };
        assert_eq!(status, 0, "native graph-context retain refused");
        Self {
            runtime: self.runtime,
            handle: Some(handle),
        }
    }
}

pub struct NativeModuleRecord<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
}

fn release(runtime: &NativeModuleRuntime<'_>, handle: &mut Option<NativeModuleHandle>) {
    let Some(handle) = handle.take() else {
        return;
    };
    let status =
        unsafe { ex_hermes_module_release_handle(runtime.raw.as_ptr(), runtime.nonce, handle) };
    debug_assert_eq!(status, 0, "native module-runner handle release refused");
}

impl Drop for CompiledModuleFactory<'_> {
    fn drop(&mut self) {
        release(self.runtime, &mut self.handle);
    }
}

impl Drop for NativeGraphContext<'_> {
    fn drop(&mut self) {
        release(self.runtime, &mut self.handle);
    }
}

impl Drop for NativeModuleRecord<'_> {
    fn drop(&mut self) {
        release(self.runtime, &mut self.handle);
    }
}

fn take_error(error: *mut c_char) -> String {
    if error.is_null() {
        return "no native diagnostic".into();
    }
    let detail = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    unsafe { ex_hermes_free_string(error) };
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        digest_bytes, ArtifactAdmissionV1, CanonicalSourceId, ModuleArtifactV1, ModuleSemanticsV1,
        ProducerIdentityV1, SourceDialectV1, SourceGoalV1, SourceMapV1, TransformFingerprintV1,
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use capsec_semantics::model::{Digest, NonEmptyString, PathComponent, Principal};

    #[allow(clashing_extern_declarations)]
    unsafe extern "C" {
        fn ex_hermes_create_diagnostic() -> *mut c_void;
        fn ex_hermes_runtime_nonce(runtime: *mut c_void) -> u64;
        fn ex_hermes_destroy(runtime: *mut c_void);
    }

    fn digest(label: &str) -> Digest {
        digest_bytes("module-runner-test", label.as_bytes()).unwrap()
    }

    fn test_artifact(source_id: SourceId) -> ModuleArtifactV1 {
        let factory =
            "function () { return { declare: function () {}, execute: function () {} }; }";
        let fingerprint = TransformFingerprintV1 {
            producer: NonEmptyString::new("test-producer").unwrap(),
            parser_version: NonEmptyString::new("oxc-test").unwrap(),
            transform_version: NonEmptyString::new("transform-test").unwrap(),
            hermes_target: NonEmptyString::new("hermes-test").unwrap(),
            typescript_jsx_options_digest: digest("ts-jsx"),
            module_runner_abi: NonEmptyString::new("ibex-module-runner-1").unwrap(),
            hermes_compat_version: NonEmptyString::new("compat-test").unwrap(),
            commonjs_detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
            commonjs_detector_version: NonEmptyString::new("2.1.0").unwrap(),
            output_options_digest: digest("output"),
        };
        ModuleArtifactV1::new_inline(
            ModuleSemanticsV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_goal: SourceGoalV1::Module,
                dialect: Some(SourceDialectV1::Js),
                source_integrity: digest("source"),
                transform_fingerprint: fingerprint,
                static_edges: Vec::new(),
                export_descriptors: Vec::new(),
                commonjs_exports: None,
                has_top_level_await: false,
                factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                    .unwrap(),
                source_map: SourceMapV1 {
                    version: 3,
                    source_ids: vec![CanonicalSourceId(source_id)],
                    names: Vec::new(),
                    mappings: String::new(),
                },
            },
            factory.into(),
            ProducerIdentityV1::InProcess {
                producer_id: NonEmptyString::new("test-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
            },
        )
        .unwrap()
    }

    #[test]
    fn native_handle_has_no_pointer_or_javascript_identity() {
        assert_eq!(std::mem::size_of::<NativeModuleHandle>(), 24);
        assert_eq!(NativeModuleHandle::default().opaque, [0, 0, 0]);
        assert!(!std::mem::needs_drop::<NativeModuleHandle>());
    }

    #[test]
    fn graph_context_canonicalizes_the_constrained_principal_set() {
        let source_id = SourceId::file(
            Principal::Root {
                identity: NonEmptyString::new("project").unwrap(),
            },
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let context = GraphEvaluationContext::new(source_id, 4, 3, [9, 3, 9, 4], 7).unwrap();
        assert_eq!(context.constrained_principals, vec![3, 4, 9]);
        assert_eq!(context.graph_generation, 7);
    }

    #[test]
    fn verified_factory_context_and_record_are_generation_scoped() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let source_id = SourceId::synthetic("module-runner-test", "entry").unwrap();
            let artifact = test_artifact(source_id.clone());
            let verified = artifact
                .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                    expected_source_id: source_id.clone(),
                    expected_source_integrity: digest("source"),
                    expected_producer_id: NonEmptyString::new("test-runtime").unwrap(),
                    producer_binary_digest: digest("producer"),
                    transform_fingerprint_digest: artifact
                        .semantics
                        .transform_fingerprint
                        .digest()
                        .unwrap(),
                })
                .unwrap();
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let retained_context = context.clone();
            let factory = runtime
                .compile_verified_factory(verified, 0, None, 1, "entry.mjs")
                .unwrap();
            let record = factory.create_record(&context, &source_id).unwrap();
            drop(record);
            drop(factory);
            drop(retained_context);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }
}
