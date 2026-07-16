//! Safe Rust ownership over the native Hermes module-runner capabilities.
//!
//! The only factory compilation entry accepts a verified artifact capability;
//! raw/deserialized artifacts cannot reach the C++ compiler through this API.
//! @ref LLP 0027#canonical-encoding-and-validation

#[cfg(any(test, feature = "module-runner"))]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::ffi::CString;
use std::ffi::{c_char, c_void, CStr};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use anyhow::{anyhow, bail, Result};

use crate::module_loader::artifact::{ModulePayloadV1, SourceGoalV1, VerifiedModuleArtifactV1};
use crate::module_loader::carrier::{PreparedCarrierEncodingV1, VerifiedPreparedCarrierEntryV1};
#[cfg(any(test, feature = "module-runner"))]
use crate::module_loader::graph::{AsyncEvaluationPlan, SynchronousGraphPlan};
use crate::module_loader::identity::SourceId;
#[cfg(any(test, feature = "module-runner"))]
use crate::module_loader::security::{
    AuthorizedGraphOperation, GraphAuthorityContext, GraphImportPolicy, ModuleGraphAuthorizer,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeModuleHandle {
    opaque: [u64; 3],
}

unsafe extern "C" {
    fn ex_hermes_module_compile_factory(
        runtime: *mut c_void,
        runtime_nonce: u64,
        source_goal: u32,
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
    fn ex_hermes_module_load_carrier_factory(
        runtime: *mut c_void,
        runtime_nonce: u64,
        source_goal: u32,
        principal_id: u32,
        graph_generation: u64,
        compartment_identity: *const u8,
        compartment_identity_len: usize,
        semantic_digest: *const u8,
        semantic_digest_len: usize,
        source_id: *const u8,
        source_id_len: usize,
        carrier_digest: *const u8,
        carrier_digest_len: usize,
        carrier_bytes: *const u8,
        carrier_bytes_len: usize,
        carrier_encoding: u32,
        entry_id: *const u8,
        entry_id_len: usize,
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
    fn ex_hermes_commonjs_create_record(
        runtime: *mut c_void,
        runtime_nonce: u64,
        factory: NativeModuleHandle,
        context: NativeModuleHandle,
        source_id: *const u8,
        source_id_len: usize,
        filename: *const u8,
        filename_len: usize,
        dirname: *const u8,
        dirname_len: usize,
        out_record: *mut NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_record_declare_export(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        export_name: *const u8,
        export_name_len: usize,
    ) -> i32;
    fn ex_hermes_commonjs_record_link_require(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_record_link_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_record_evaluate(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_evicted: *mut i32,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_commonjs_record_create_esm_adapter(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_adapter: *mut NativeModuleHandle,
        out_error: *mut *mut c_char,
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
    fn ex_hermes_module_record_declare_export(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        export_name: *const u8,
        export_name_len: usize,
    ) -> i32;
    fn ex_hermes_module_record_link_export(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        export_name: *const u8,
        export_name_len: usize,
        target_record: NativeModuleHandle,
        target_export: *const u8,
        target_export_len: usize,
    ) -> i32;
    fn ex_hermes_module_record_link_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        imported_name: *const u8,
        imported_name_len: usize,
        target_record: NativeModuleHandle,
        target_export: *const u8,
        target_export_len: usize,
    ) -> i32;
    #[cfg(any(test, feature = "module-runner"))]
    fn ex_hermes_module_record_link_dependency(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        target_record: NativeModuleHandle,
    ) -> i32;
    #[cfg(any(test, feature = "module-runner"))]
    fn ex_hermes_module_record_link_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_module_record_instantiate(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        meta_url: *const u8,
        meta_url_len: usize,
        is_main: i32,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_module_record_run_declare(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_module_record_run_execute(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_async: *mut i32,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_module_record_poll_evaluation(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_state: *mut i32,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_module_record_namespace_json(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_json: *mut *mut c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut c_char);
    #[cfg(test)]
    fn ex_hermes_eval(
        runtime: *mut c_void,
        data: *const u8,
        len: usize,
        source_url: *const c_char,
        is_bytecode: i32,
        out_value: *mut *mut c_char,
    ) -> i32;
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
        self.compile_verified_factory_for_goal(
            verified,
            SourceGoalV1::Module,
            0,
            principal_id,
            compartment_identity,
            graph_generation,
            source_label,
        )
    }

    pub fn compile_verified_commonjs_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        self.compile_verified_factory_for_goal(
            verified,
            SourceGoalV1::CommonJs,
            1,
            principal_id,
            compartment_identity,
            graph_generation,
            source_label,
        )
    }

    fn compile_verified_factory_for_goal(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        expected_goal: SourceGoalV1,
        native_goal: u32,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        if graph_generation == 0 {
            bail!("module graph generation must be nonzero");
        }
        let artifact = verified.artifact();
        if artifact.semantics.source_goal != expected_goal {
            bail!("factory compilation received the wrong source-goal artifact");
        }
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
                native_goal,
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

    /// Load one factory from an already-admitted, per-principal prepared
    /// carrier. Both capabilities must agree on the physical carrier entry and
    /// on the original module semantics before any carrier byte is evaluated.
    pub fn load_verified_prepared_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        carrier_entry: VerifiedPreparedCarrierEntryV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        if graph_generation == 0 {
            bail!("module graph generation must be nonzero");
        }
        let artifact = verified.artifact();
        let (carrier_digest, entry_id, entry_factory_digest) = match &artifact.payload {
            ModulePayloadV1::Carrier {
                carrier_digest,
                entry_id,
                entry_factory_digest,
            } => (carrier_digest, entry_id, entry_factory_digest),
            ModulePayloadV1::Inline { .. } => {
                bail!("prepared factory loading requires a carrier artifact")
            }
        };
        let manifest = carrier_entry.manifest();
        let entry = carrier_entry.entry();
        if carrier_digest != &manifest.carrier_digest
            || entry_id != &entry.entry_id
            || entry_factory_digest != &entry.semantics.factory_digest
            || artifact.semantic_digest != entry.semantic_digest
            || artifact.semantics != entry.semantics
        {
            bail!("prepared carrier entry does not match the admitted module artifact");
        }
        let native_goal = match artifact.semantics.source_goal {
            SourceGoalV1::Module => 0,
            SourceGoalV1::CommonJs => 1,
            SourceGoalV1::Json | SourceGoalV1::Builtin => {
                bail!("prepared factory loading requires an executable source goal")
            }
        };
        let native_encoding = match &manifest.encoding {
            PreparedCarrierEncodingV1::JavascriptFactoryTable => 0,
            PreparedCarrierEncodingV1::HermesBytecode { .. } => 1,
        };
        let compartment = compartment_identity.unwrap_or("");
        let digest = artifact.semantic_digest.as_str();
        let source_id = artifact.semantics.source_id.0.encode()?;
        let mut handle = NativeModuleHandle::default();
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_load_carrier_factory(
                self.raw.as_ptr(),
                self.nonce,
                native_goal,
                principal_id,
                graph_generation,
                compartment.as_ptr(),
                compartment.len(),
                digest.as_ptr(),
                digest.len(),
                source_id.as_ptr(),
                source_id.len(),
                manifest.carrier_digest.as_str().as_ptr(),
                manifest.carrier_digest.as_str().len(),
                carrier_entry.bytes().as_ptr(),
                carrier_entry.bytes().len(),
                native_encoding,
                entry.entry_id.as_str().as_ptr(),
                entry.entry_id.as_str().len(),
                source_label.as_ptr(),
                source_label.len(),
                &mut handle,
                &mut error,
            )
        };
        if status != 0 {
            let detail = take_error(error);
            if status == 2 {
                bail!("prepared Hermes bytecode refused before execution: {detail}");
            }
            bail!("native prepared module factory load refused ({status}): {detail}");
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

#[derive(Debug, Clone)]
pub struct NativeModuleRecordConfig {
    pub principal_id: u32,
    pub compartment_identity: Option<String>,
    pub evaluation_context: GraphEvaluationContext,
    pub source_label: String,
    pub meta_url: String,
}

impl NativeModuleRecordConfig {
    pub fn new(
        principal_id: u32,
        compartment_identity: Option<String>,
        evaluation_context: GraphEvaluationContext,
        source_label: impl Into<String>,
        meta_url: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            principal_id,
            compartment_identity,
            evaluation_context,
            source_label: source_label.into(),
            meta_url: meta_url.into(),
        };
        if value.source_label.is_empty() {
            bail!("module source label must not be empty");
        }
        if value.meta_url.is_empty() {
            bail!("module import.meta URL must not be empty");
        }
        value.evaluation_context.validate()?;
        Ok(value)
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

    pub fn create_commonjs_record(
        &self,
        context: &NativeGraphContext<'runtime>,
        source_id: &SourceId,
        filename: &str,
        dirname: &str,
    ) -> Result<NativeCommonJsRecord<'runtime>> {
        if !std::ptr::eq(self.runtime, context.runtime) {
            bail!("factory and graph context belong to different runtime borrows");
        }
        if filename.is_empty() {
            bail!("CommonJS filename must not be empty");
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
            ex_hermes_commonjs_create_record(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                factory,
                context_handle,
                source_id.as_ptr(),
                source_id.len(),
                filename.as_ptr(),
                filename.len(),
                dirname.as_ptr(),
                dirname.len(),
                &mut record,
            )
        };
        if status != 0 {
            bail!("native CommonJS record creation refused ({status})");
        }
        Ok(NativeCommonJsRecord {
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

pub struct NativeCommonJsRecord<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
}

// @ref LLP 0027#esmcommonjs-interop-matrix — native CommonJS records retain
// early-publication/eviction semantics and mint snapshot ESM adapters.
impl<'runtime> NativeCommonJsRecord<'runtime> {
    fn live_handle(&self) -> Result<NativeModuleHandle> {
        self.handle
            .ok_or_else(|| anyhow!("native CommonJS record was evicted or released"))
    }

    pub fn declare_detected_export(&mut self, export_name: &str) -> Result<()> {
        if export_name.is_empty() {
            bail!("CommonJS detected export name must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_declare_export(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                export_name.as_ptr(),
                export_name.len(),
            )
        };
        if status != 0 {
            bail!("native CommonJS export declaration refused ({status})");
        }
        Ok(())
    }

    pub fn link_require(
        &mut self,
        specifier: &str,
        target: &NativeCommonJsRecord<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("CommonJS records belong to different runtime borrows");
        }
        if specifier.is_empty() {
            bail!("CommonJS require specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_require(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target.live_handle()?,
            )
        };
        if status != 0 {
            bail!("native CommonJS require link refused ({status})");
        }
        Ok(())
    }

    pub fn link_dynamic_import(
        &mut self,
        specifier: &str,
        target: &NativeModuleRecord<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("CommonJS and ESM records belong to different runtime borrows");
        }
        if specifier.is_empty() {
            bail!("CommonJS dynamic-import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target.live_handle()?,
            )
        };
        if status != 0 {
            bail!("native CommonJS dynamic-import link refused ({status})");
        }
        Ok(())
    }

    pub fn evaluate(&mut self) -> Result<()> {
        let handle = self.live_handle()?;
        let mut evicted = 0;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_commonjs_record_evaluate(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                handle,
                &mut evicted,
                &mut error,
            )
        };
        if evicted == 1 {
            self.handle = None;
        }
        native_result(status, error, "CommonJS record evaluation")
    }

    pub fn create_esm_adapter(&self) -> Result<NativeModuleRecord<'runtime>> {
        let mut adapter = NativeModuleHandle::default();
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_commonjs_record_create_esm_adapter(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut adapter,
                &mut error,
            )
        };
        native_result(status, error, "CommonJS ESM-adapter creation")?;
        Ok(NativeModuleRecord {
            runtime: self.runtime,
            handle: Some(adapter),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleExecutionKind {
    Synchronous,
    Asynchronous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleEvaluationState {
    Pending,
    Evaluated,
}

impl NativeModuleRecord<'_> {
    fn live_handle(&self) -> Result<NativeModuleHandle> {
        self.handle
            .ok_or_else(|| anyhow!("native ModuleRecord capability was released"))
    }

    pub fn declare_export(&mut self, export_name: &str) -> Result<()> {
        if export_name.is_empty() {
            bail!("module export name must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_declare_export(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                export_name.as_ptr(),
                export_name.len(),
            )
        };
        if status != 0 {
            bail!("native export-cell declaration refused ({status})");
        }
        Ok(())
    }

    pub fn link_import(
        &mut self,
        specifier: &str,
        imported_name: &str,
        target: &NativeModuleRecord<'_>,
        target_export: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("module import records belong to different runtime borrows");
        }
        if specifier.is_empty() || imported_name.is_empty() || target_export.is_empty() {
            bail!("module import binding strings must not be empty");
        }
        self.link_import_handle(
            specifier,
            imported_name,
            target.live_handle()?,
            target_export,
        )
    }

    fn link_import_handle(
        &mut self,
        specifier: &str,
        imported_name: &str,
        target: NativeModuleHandle,
        target_export: &str,
    ) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_record_link_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                imported_name.as_ptr(),
                imported_name.len(),
                target,
                target_export.as_ptr(),
                target_export.len(),
            )
        };
        if status != 0 {
            bail!("native import binding refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn link_dependency_handle(&mut self, target: NativeModuleHandle) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_record_link_dependency(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                target,
            )
        };
        if status != 0 {
            bail!("native evaluation dependency refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn link_dynamic_import_handle(
        &mut self,
        specifier: &str,
        target: NativeModuleHandle,
    ) -> Result<()> {
        if specifier.is_empty() {
            bail!("dynamic import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_link_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target,
            )
        };
        if status != 0 {
            bail!("native dynamic import binding refused ({status})");
        }
        Ok(())
    }

    /// Link a declared export as a live view of another record's export or
    /// namespace (`target_export == "*"`). The target must belong to the same
    /// runtime and graph generation.
    pub fn link_export(
        &mut self,
        export_name: &str,
        target: &NativeModuleRecord<'_>,
        target_export: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("module export records belong to different runtime borrows");
        }
        if export_name.is_empty() || target_export.is_empty() {
            bail!("module export binding strings must not be empty");
        }
        self.link_export_handle(export_name, target.live_handle()?, target_export)
    }

    fn link_export_handle(
        &mut self,
        export_name: &str,
        target: NativeModuleHandle,
        target_export: &str,
    ) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_record_link_export(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                export_name.as_ptr(),
                export_name.len(),
                target,
                target_export.as_ptr(),
                target_export.len(),
            )
        };
        if status != 0 {
            bail!("native export binding refused ({status})");
        }
        Ok(())
    }

    pub fn instantiate(&mut self, meta_url: &str, is_main: bool) -> Result<()> {
        if meta_url.is_empty() {
            bail!("module import.meta URL must not be empty");
        }
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_record_instantiate(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                meta_url.as_ptr(),
                meta_url.len(),
                i32::from(is_main),
                &mut error,
            )
        };
        native_result(status, error, "ModuleRecord instantiation")
    }

    pub fn run_declare(&mut self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_record_run_declare(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut error,
            )
        };
        native_result(status, error, "ModuleRecord declaration")
    }

    pub fn run_execute(&mut self) -> Result<ModuleExecutionKind> {
        let mut asynchronous = 0;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_record_run_execute(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut asynchronous,
                &mut error,
            )
        };
        native_result(status, error, "ModuleRecord execution")?;
        match asynchronous {
            0 => Ok(ModuleExecutionKind::Synchronous),
            1 => Ok(ModuleExecutionKind::Asynchronous),
            _ => bail!("native ModuleRecord returned an invalid execution kind"),
        }
    }

    /// Poll the one internal evaluation promise owned by this record. This is
    /// deliberately state-only: callers drive Hermes separately and never
    /// wait on the runtime thread.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn poll_evaluation(&self) -> Result<ModuleEvaluationState> {
        let mut state = -1;
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_record_poll_evaluation(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut state,
                &mut error,
            )
        };
        native_result(status, error, "ModuleRecord evaluation poll")?;
        match state {
            0 => Ok(ModuleEvaluationState::Pending),
            1 => Ok(ModuleEvaluationState::Evaluated),
            _ => bail!("native ModuleRecord returned an invalid evaluation state"),
        }
    }

    pub fn namespace_json(&self) -> Result<String> {
        let mut json = std::ptr::null_mut();
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_module_record_namespace_json(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut json,
                &mut error,
            )
        };
        native_result(status, error, "ModuleRecord namespace read")?;
        if json.is_null() {
            bail!("native ModuleRecord namespace read returned no JSON");
        }
        let value = unsafe { CStr::from_ptr(json) }
            .to_string_lossy()
            .into_owned();
        unsafe { ex_hermes_free_string(json) };
        Ok(value)
    }
}

/// Fully linked synchronous graph whose reachable records have all completed
/// factory instantiation and declaration before any module body may execute.
// @ref LLP 0026#5-esm-record-lifecycle — full-closure linking precedes body
// evaluation, and cycles reuse the already-created native records.
#[cfg(any(test, feature = "module-runner"))]
pub struct NativeSynchronousGraph<'runtime> {
    entry: SourceId,
    evaluation_order: Vec<SourceId>,
    records: BTreeMap<SourceId, NativeModuleRecord<'runtime>>,
    evaluation_outcome: Option<std::result::Result<(), String>>,
    _authorization_receipts: Vec<AuthorizedGraphOperation>,
}

#[cfg(any(test, feature = "module-runner"))]
impl<'runtime> NativeSynchronousGraph<'runtime> {
    /// Production graph entry: authenticate the complete reachable edge set
    /// before compiling the first factory.
    pub fn link_authorized<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            receipts,
            Some(dynamic.allowed_specifiers),
            None,
        )
    }

    /// Prepared-graph entry. Carrier capabilities were admitted atomically by
    /// the trusted loader and are matched to the same verified semantic plan.
    pub fn link_authorized_prepared<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV1<'_>>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            receipts,
            Some(dynamic.allowed_specifiers),
            Some(prepared_entries),
        )
    }

    /// Diagnostic-only bypass for native ABI unit fixtures. Advertised builds
    /// have no unauthenticated graph-link entry.
    #[cfg(test)]
    pub fn link(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            Vec::new(),
            None,
            None,
        )
    }

    #[cfg(test)]
    pub fn link_prepared(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV1<'_>>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            Vec::new(),
            None,
            Some(prepared_entries),
        )
    }

    fn link_inner(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        evaluation_order: Vec<SourceId>,
        mut configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorization_receipts: Vec<AuthorizedGraphOperation>,
        allowed_dynamic_specifiers: Option<BTreeMap<SourceId, BTreeSet<String>>>,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV1<'_>>>,
    ) -> Result<Self> {
        let linkage_order = match &allowed_dynamic_specifiers {
            Some(allowed) => plan.linkage_order_for_authorized(entry, allowed)?,
            None => plan.linkage_order(entry)?,
        };
        if let Some(outside) = configs
            .keys()
            .find(|source_id| !plan.contains_record(source_id))
        {
            bail!(
                "native configuration contains record outside the authenticated plan: {outside:?}"
            );
        }
        let generation = configs
            .get(entry)
            .ok_or_else(|| anyhow!("entry ModuleRecord has no native configuration"))?
            .evaluation_context
            .graph_generation;
        let mut records = BTreeMap::new();
        let mut meta_urls = BTreeMap::new();

        // Create every reachable record before publishing cells or links. The
        // native record retains its context and callable factory handles.
        for source_id in &linkage_order {
            let config = configs.remove(source_id).ok_or_else(|| {
                anyhow!("reachable ModuleRecord {source_id:?} has no native configuration")
            })?;
            if config.evaluation_context.requesting_record != *source_id {
                bail!("ModuleRecord context requester does not match {source_id:?}");
            }
            if config.evaluation_context.graph_generation != generation {
                bail!("synchronous graph mixes execution generations");
            }
            let context = runtime.create_graph_context(config.evaluation_context)?;
            let verified = plan.artifact(source_id)?;
            let factory = match prepared_entries {
                Some(entries) => runtime.load_verified_prepared_factory(
                    verified,
                    *entries.get(source_id).ok_or_else(|| {
                        anyhow!("prepared graph has no admitted carrier entry for {source_id:?}")
                    })?,
                    config.principal_id,
                    config.compartment_identity.as_deref(),
                    generation,
                    &config.source_label,
                )?,
                None => runtime.compile_verified_factory(
                    verified,
                    config.principal_id,
                    config.compartment_identity.as_deref(),
                    generation,
                    &config.source_label,
                )?,
            };
            let record = factory.create_record(&context, source_id)?;
            records.insert(source_id.clone(), record);
            meta_urls.insert(source_id.clone(), config.meta_url);
        }
        // Configurations for denied or unselected dynamic candidates remain
        // inert: no native record, factory compilation, or call-time table
        // entry is created for them.

        // Materialize every namespace shape before linking any aliases. This
        // is the cycle boundary: every record identity and cell already exists.
        for source_id in &linkage_order {
            let namespace = plan.namespace(source_id)?;
            let record = records
                .get_mut(source_id)
                .expect("evaluation order was used to create every record");
            for export_name in namespace.keys() {
                record.declare_export(export_name)?;
            }
        }

        for source_id in &linkage_order {
            for (export_name, target) in plan.namespace(source_id)? {
                if target.record == *source_id && target.binding == export_name {
                    continue;
                }
                let target_handle = records
                    .get(&target.record)
                    .ok_or_else(|| anyhow!("export target is outside the entry closure"))?
                    .live_handle()?;
                records
                    .get_mut(source_id)
                    .expect("evaluation order was used to create every record")
                    .link_export_handle(&export_name, target_handle, &target.binding)?;
            }
            for binding in plan.import_bindings(source_id)? {
                let target_handle = records
                    .get(&binding.target.record)
                    .ok_or_else(|| anyhow!("import target is outside the entry closure"))?
                    .live_handle()?;
                records
                    .get_mut(source_id)
                    .expect("evaluation order was used to create every record")
                    .link_import_handle(
                        &binding.specifier,
                        &binding.imported,
                        target_handle,
                        &binding.target.binding,
                    )?;
            }
            let mut dependencies = BTreeSet::new();
            for edge in &plan.artifact(source_id)?.artifact().semantics.static_edges {
                let specifier = match edge {
                    crate::module_loader::artifact::StaticEdgeV1::CommonJsRequire { specifier }
                    | crate::module_loader::artifact::StaticEdgeV1::SideEffect {
                        specifier, ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::Default { specifier, .. }
                    | crate::module_loader::artifact::StaticEdgeV1::Namespace {
                        specifier, ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::Named { specifier, .. }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportNamed {
                        specifier,
                        ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportStar {
                        specifier,
                        ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportNamespace {
                        specifier,
                        ..
                    } => specifier.as_str(),
                };
                let target = plan.literal_static_target(source_id, specifier)?.clone();
                if dependencies.insert(target.clone()) {
                    let target_handle = records
                        .get(&target)
                        .ok_or_else(|| anyhow!("evaluation dependency is outside linkage closure"))?
                        .live_handle()?;
                    records
                        .get_mut(source_id)
                        .expect("linkage order was used to create every record")
                        .link_dependency_handle(target_handle)?;
                }
            }
            for (specifier, target) in plan.dynamic_import_targets(source_id)? {
                if allowed_dynamic_specifiers.as_ref().is_some_and(|allowed| {
                    !allowed
                        .get(source_id)
                        .is_some_and(|specifiers| specifiers.contains(&specifier))
                }) {
                    continue;
                }
                let target_handle = records
                    .get(&target)
                    .ok_or_else(|| anyhow!("dynamic import target is outside linkage closure"))?
                    .live_handle()?;
                records
                    .get_mut(source_id)
                    .expect("linkage order was used to create every record")
                    .link_dynamic_import_handle(&specifier, target_handle)?;
            }
        }

        // Complete graph-wide instantiation and declaration before the first
        // body executes. Dependency-first order also matches the synchronous
        // DFS evaluation order for cycles and acyclic graphs.
        for source_id in &linkage_order {
            let meta_url = meta_urls
                .get(source_id)
                .expect("every configured record has an import.meta URL");
            records
                .get_mut(source_id)
                .expect("evaluation order was used to create every record")
                .instantiate(meta_url, source_id == entry)?;
        }
        for source_id in &linkage_order {
            records
                .get_mut(source_id)
                .expect("evaluation order was used to create every record")
                .run_declare()?;
        }

        Ok(Self {
            entry: entry.clone(),
            evaluation_order,
            records,
            evaluation_outcome: None,
            _authorization_receipts: authorization_receipts,
        })
    }

    pub fn evaluate(&mut self) -> Result<()> {
        if let Some(outcome) = &self.evaluation_outcome {
            return outcome.clone().map_err(|detail| anyhow!(detail));
        }
        let outcome = (|| {
            for source_id in &self.evaluation_order {
                let kind = self
                    .records
                    .get_mut(source_id)
                    .expect("linked graph retains every reachable record")
                    .run_execute()?;
                if kind == ModuleExecutionKind::Asynchronous {
                    bail!(
                        "ERR_REQUIRE_ASYNC_MODULE: synchronous artifact returned a promise in {source_id:?}"
                    );
                }
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                self.evaluation_outcome = Some(Ok(()));
                Ok(())
            }
            Err(error) => {
                let detail = error.to_string();
                self.evaluation_outcome = Some(Err(detail.clone()));
                Err(anyhow!(detail))
            }
        }
    }

    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    pub fn namespace_json(&self, source_id: &SourceId) -> Result<String> {
        self.records
            .get(source_id)
            .ok_or_else(|| anyhow!("namespace requested outside the linked entry closure"))?
            .namespace_json()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncGraphPoll {
    Suspended,
    Evaluated,
}

/// A linked ESM graph whose dependency-first progress is driven by polling.
/// The graph owns every internal record promise until terminal settlement;
/// callers drive the Hermes microtask/event loop between `poll` calls and no
/// runtime thread is ever blocked.
// @ref LLP 0024#7-the-session-record
// @ref LLP 0025#6-interruption-and-cancellation
#[cfg(any(test, feature = "module-runner"))]
pub struct NativeAsynchronousGraph<'runtime> {
    entry: SourceId,
    schedule: AsyncEvaluationPlan,
    records: BTreeMap<SourceId, NativeModuleRecord<'runtime>>,
    next_scc: usize,
    suspended_records: Vec<SourceId>,
    evaluation_outcome: Option<std::result::Result<(), String>>,
    _authorization_receipts: Vec<AuthorizedGraphOperation>,
}

#[cfg(any(test, feature = "module-runner"))]
impl<'runtime> NativeAsynchronousGraph<'runtime> {
    pub fn link_authorized<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
    ) -> Result<Self> {
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            schedule,
            configs,
            receipts,
            Some(dynamic.allowed_specifiers),
            None,
        )
    }

    pub fn link_authorized_prepared<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV1<'_>>,
    ) -> Result<Self> {
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            schedule,
            configs,
            receipts,
            Some(dynamic.allowed_specifiers),
            Some(prepared_entries),
        )
    }

    #[cfg(test)]
    pub fn link(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
    ) -> Result<Self> {
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            schedule,
            configs,
            Vec::new(),
            None,
            None,
        )
    }

    fn link_inner(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        schedule: AsyncEvaluationPlan,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorization_receipts: Vec<AuthorizedGraphOperation>,
        allowed_dynamic_specifiers: Option<BTreeMap<SourceId, BTreeSet<String>>>,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV1<'_>>>,
    ) -> Result<Self> {
        let linked = NativeSynchronousGraph::link_inner(
            runtime,
            plan,
            entry,
            schedule.evaluation_order.clone(),
            configs,
            authorization_receipts,
            allowed_dynamic_specifiers,
            prepared_entries,
        )?;
        let NativeSynchronousGraph {
            entry,
            records,
            _authorization_receipts,
            ..
        } = linked;
        Ok(Self {
            entry,
            schedule,
            records,
            next_scc: 0,
            suspended_records: Vec::new(),
            evaluation_outcome: None,
            _authorization_receipts,
        })
    }

    /// Make deterministic progress until the next TLA suspension or terminal
    /// outcome. A native rejection becomes the graph's sticky error and every
    /// later poll reports the same diagnostic.
    pub fn poll(&mut self) -> Result<AsyncGraphPoll> {
        if let Some(outcome) = &self.evaluation_outcome {
            return outcome
                .clone()
                .map(|()| AsyncGraphPoll::Evaluated)
                .map_err(|detail| anyhow!(detail));
        }
        let outcome: Result<AsyncGraphPoll> = (|| {
            if !self.suspended_records.is_empty() {
                let mut pending = Vec::new();
                for source_id in self.suspended_records.drain(..) {
                    match self
                        .records
                        .get(&source_id)
                        .expect("suspended record remains owned by its graph")
                        .poll_evaluation()?
                    {
                        ModuleEvaluationState::Pending => pending.push(source_id),
                        ModuleEvaluationState::Evaluated => {}
                    }
                }
                self.suspended_records = pending;
                if !self.suspended_records.is_empty() {
                    return Ok(AsyncGraphPoll::Suspended);
                }
                self.next_scc += 1;
            }

            while self.next_scc < self.schedule.sccs.len() {
                // All records in one SCC must be allowed to start before the
                // component waits. Otherwise one TLA record can suspend ahead
                // of a cyclic peer whose body is required to settle it.
                // @ref LLP 0026#6-top-level-await-and-dynamic-import
                for source_id in self.schedule.sccs[self.next_scc].records.clone() {
                    let kind = self
                        .records
                        .get_mut(&source_id)
                        .expect("async schedule retains every reachable record")
                        .run_execute()?;
                    if kind == ModuleExecutionKind::Asynchronous {
                        self.suspended_records.push(source_id);
                    }
                }
                if !self.suspended_records.is_empty() {
                    return Ok(AsyncGraphPoll::Suspended);
                }
                self.next_scc += 1;
            }
            Ok(AsyncGraphPoll::Evaluated)
        })();
        match outcome {
            Ok(AsyncGraphPoll::Evaluated) => {
                self.evaluation_outcome = Some(Ok(()));
                Ok(AsyncGraphPoll::Evaluated)
            }
            Ok(AsyncGraphPoll::Suspended) => Ok(AsyncGraphPoll::Suspended),
            Err(error) => {
                let detail = error.to_string();
                self.evaluation_outcome = Some(Err(detail.clone()));
                Err(anyhow!(detail))
            }
        }
    }

    pub fn is_suspended(&self) -> bool {
        !self.suspended_records.is_empty()
    }

    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    pub fn schedule(&self) -> &AsyncEvaluationPlan {
        &self.schedule
    }

    pub fn namespace_json(&self, source_id: &SourceId) -> Result<String> {
        self.records
            .get(source_id)
            .ok_or_else(|| anyhow!("namespace requested outside the linked entry closure"))?
            .namespace_json()
    }
}

fn release(runtime: &NativeModuleRuntime<'_>, handle: &mut Option<NativeModuleHandle>) {
    let Some(handle) = handle.take() else {
        return;
    };
    let status =
        unsafe { ex_hermes_module_release_handle(runtime.raw.as_ptr(), runtime.nonce, handle) };
    debug_assert!(
        status == 0 || status == -2,
        "native module-runner handle release refused ({status})"
    );
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

impl Drop for NativeCommonJsRecord<'_> {
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

fn native_result(status: i32, error: *mut c_char, operation: &str) -> Result<()> {
    if status != 0 {
        let detail = take_error(error);
        bail!("native {operation} refused ({status}): {detail}");
    }
    if !error.is_null() {
        unsafe { ex_hermes_free_string(error) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        digest_bytes, ArtifactAdmissionV1, CanonicalSourceId, CommonJsExportsV1, DynamicEdgeV1,
        ExportDescriptorV1, ModuleArtifactV1, ModuleSemanticsV1, ProducerIdentityV1,
        SourceDialectV1, SourceGoalV1, SourceMapV1, StaticEdgeV1, TransformFingerprintV1,
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::carrier::{
        AdmittedPreparedCarrierV1, PreparedCarrierAdmissionV1, PreparedModuleCarrierV1,
    };
    use crate::module_loader::identity::ImportAttributes;
    use capsec_semantics::model::{Digest, NonEmptyString, PathComponent, Principal};

    #[allow(clashing_extern_declarations)]
    unsafe extern "C" {
        fn ex_hermes_create_diagnostic() -> *mut c_void;
        fn ex_hermes_runtime_nonce(runtime: *mut c_void) -> u64;
        fn ex_hermes_poll(runtime: *mut c_void, now_ms: u64) -> i32;
        fn ex_hermes_destroy(runtime: *mut c_void);
    }

    fn digest(label: &str) -> Digest {
        digest_bytes("module-runner-test", label.as_bytes()).unwrap()
    }

    fn test_artifact_with_factory(
        source_id: SourceId,
        factory: &str,
        exports: &[&str],
    ) -> ModuleArtifactV1 {
        test_graph_artifact(
            source_id,
            factory,
            Vec::new(),
            exports
                .iter()
                .map(|name| ExportDescriptorV1::Local {
                    exported: NonEmptyString::new(*name).unwrap(),
                    local: NonEmptyString::new(*name).unwrap(),
                })
                .collect(),
        )
    }

    fn test_graph_artifact(
        source_id: SourceId,
        factory: &str,
        static_edges: Vec<StaticEdgeV1>,
        export_descriptors: Vec<ExportDescriptorV1>,
    ) -> ModuleArtifactV1 {
        test_artifact_for_goal(
            source_id,
            factory,
            SourceGoalV1::Module,
            static_edges,
            export_descriptors,
            None,
        )
    }

    fn test_commonjs_artifact(
        source_id: SourceId,
        factory: &str,
        detected_names: &[&str],
    ) -> ModuleArtifactV1 {
        test_artifact_for_goal(
            source_id,
            factory,
            SourceGoalV1::CommonJs,
            Vec::new(),
            Vec::new(),
            Some(CommonJsExportsV1 {
                detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                detector_version: NonEmptyString::new("2.1.0").unwrap(),
                names: detected_names
                    .iter()
                    .map(|name| NonEmptyString::new(*name).unwrap())
                    .collect(),
                reexports: Vec::new(),
            }),
        )
    }

    fn test_artifact_for_goal(
        source_id: SourceId,
        factory: &str,
        source_goal: SourceGoalV1,
        static_edges: Vec<StaticEdgeV1>,
        export_descriptors: Vec<ExportDescriptorV1>,
        commonjs_exports: Option<CommonJsExportsV1>,
    ) -> ModuleArtifactV1 {
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
                source_goal,
                dialect: Some(SourceDialectV1::Js),
                source_integrity: digest("source"),
                transform_fingerprint: fingerprint,
                static_edges,
                dynamic_edges: Vec::new(),
                export_descriptors,
                commonjs_exports,
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

    fn test_artifact(source_id: SourceId) -> ModuleArtifactV1 {
        test_artifact_with_factory(
            source_id,
            "function ($export) { return { declare: function () {}, execute: function () { $export('value', 42); } }; }",
            &["value"],
        )
    }

    fn asynchronous_artifact(
        artifact: ModuleArtifactV1,
        dynamic_edges: Vec<DynamicEdgeV1>,
    ) -> ModuleArtifactV1 {
        let factory_source = match artifact.payload {
            crate::module_loader::artifact::ModulePayloadV1::Inline { factory_source, .. } => {
                factory_source
            }
            crate::module_loader::artifact::ModulePayloadV1::Carrier { .. } => {
                panic!("test artifacts are inline")
            }
        };
        let mut semantics = artifact.semantics;
        semantics.has_top_level_await = true;
        semantics.dynamic_edges = dynamic_edges;
        ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer).unwrap()
    }

    fn verify_test_artifact(artifact: &ModuleArtifactV1) -> VerifiedModuleArtifactV1<'_> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("test-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap()
    }

    fn prepared_admission(
        owner: Principal,
        manifest: &PreparedModuleCarrierV1,
    ) -> PreparedCarrierAdmissionV1 {
        PreparedCarrierAdmissionV1 {
            expected_principal: owner,
            expected_producer_id: NonEmptyString::new("prepared-test").unwrap(),
            producer_binary_digest: digest("prepared-producer"),
            deployment_graph_digest: digest("prepared-graph"),
            authorized_semantic_digests: manifest
                .entries
                .iter()
                .map(|entry| entry.semantic_digest.clone())
                .collect(),
            expected_engine_binary_digest: None,
            expected_bytecode_version: None,
        }
    }

    fn verify_prepared_artifact<'a>(
        artifact: &'a ModuleArtifactV1,
        manifest: &PreparedModuleCarrierV1,
    ) -> VerifiedModuleArtifactV1<'a> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::DigestBoundPrepared {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("prepared-test").unwrap(),
                producer_binary_digest: digest("prepared-producer"),
                deployment_graph_digest: digest("prepared-graph"),
                expected_carrier_digest: manifest.carrier_digest.clone(),
                expected_entry_id: NonEmptyString::new("entry").unwrap(),
                authorized_semantic_digests: [artifact.semantic_digest.clone()].into(),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
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
    fn prepared_source_and_hbc_carriers_execute_the_same_original_module() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let owner = Principal::Root {
            identity: NonEmptyString::new("prepared-project").unwrap(),
        };
        let source_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let source_artifact = test_artifact(source_id.clone());
        let (source_manifest, source_bytes) = PreparedModuleCarrierV1::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-test").unwrap(),
            digest("prepared-producer"),
            digest("prepared-graph"),
            [(
                NonEmptyString::new("entry").unwrap(),
                verify_test_artifact(&source_artifact),
            )],
        )
        .unwrap();

        let hermesc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools/hermes")
            .join(if cfg!(target_os = "windows") {
                "hermesc.exe"
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                "hermesc-macos-arm64"
            } else if cfg!(target_os = "macos") {
                "hermesc-macos-x64"
            } else if cfg!(target_arch = "aarch64") {
                "hermesc-linux-arm64"
            } else {
                "hermesc-linux-x64"
            });
        if !hermesc.is_file() {
            eprintln!(
                "skipping prepared HBC equivalence: {} is absent",
                hermesc.display()
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("carrier.js");
        let hbc_path = temp.path().join("carrier.hbc");
        std::fs::write(&source_path, &source_bytes).unwrap();
        let status = std::process::Command::new(&hermesc)
            .args(["-O", "-emit-binary", "-out"])
            .arg(&hbc_path)
            .arg(&source_path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "matching hermesc must compile the carrier"
        );
        let hbc_bytes = std::fs::read(hbc_path).unwrap();
        let engine_digest = digest("prepared-engine");
        let hbc_manifest = source_manifest
            .bind_hermes_bytecode(&hbc_bytes, engine_digest.clone(), 1)
            .unwrap();

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            for (manifest, bytes, is_hbc) in [
                (&source_manifest, source_bytes.as_slice(), false),
                (&hbc_manifest, hbc_bytes.as_slice(), true),
            ] {
                let mut admission = prepared_admission(owner.clone(), manifest);
                if is_hbc {
                    admission.expected_engine_binary_digest = Some(engine_digest.clone());
                    admission.expected_bytecode_version = Some(1);
                }
                let carrier = AdmittedPreparedCarrierV1::decode_and_admit(
                    &manifest.encode_canonical().unwrap(),
                    bytes,
                    &admission,
                )
                .unwrap();
                let prepared_artifact = manifest.prepared_artifact("entry").unwrap();
                let verified = verify_prepared_artifact(&prepared_artifact, manifest);
                let context = runtime
                    .create_graph_context(
                        GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                    )
                    .unwrap();
                let factory = runtime
                    .load_verified_prepared_factory(
                        verified,
                        carrier.entry("entry").unwrap(),
                        0,
                        None,
                        1,
                        if is_hbc { "carrier.hbc" } else { "carrier.js" },
                    )
                    .unwrap();
                let mut record = factory.create_record(&context, &source_id).unwrap();
                record.declare_export("value").unwrap();
                record
                    .instantiate("file:prepared-project/entry.mjs", true)
                    .unwrap();
                record.run_declare().unwrap();
                assert_eq!(
                    record.run_execute().unwrap(),
                    ModuleExecutionKind::Synchronous
                );
                assert_eq!(record.namespace_json().unwrap(), r#"{"value":42}"#);
            }
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn prepared_carrier_enters_the_full_graph_linker() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let owner = Principal::Root {
            identity: NonEmptyString::new("prepared-graph-project").unwrap(),
        };
        let source_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let inline = test_artifact(source_id.clone());
        let (manifest, bytes) = PreparedModuleCarrierV1::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-test").unwrap(),
            digest("prepared-producer"),
            digest("prepared-graph"),
            [(
                NonEmptyString::new("entry").unwrap(),
                verify_test_artifact(&inline),
            )],
        )
        .unwrap();
        let carrier = AdmittedPreparedCarrierV1::decode_and_admit(
            &manifest.encode_canonical().unwrap(),
            &bytes,
            &prepared_admission(owner, &manifest),
        )
        .unwrap();
        let artifact = manifest.prepared_artifact("entry").unwrap();
        let plan = SynchronousGraphPlan::new([(
            verify_prepared_artifact(&artifact, &manifest),
            BTreeMap::new(),
        )])
        .unwrap();
        let entries = BTreeMap::from([(source_id.clone(), carrier.entry("entry").unwrap())]);
        let configs = BTreeMap::from([(
            source_id.clone(),
            NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                "prepared-entry.mjs",
                "file:prepared-graph-project/entry.mjs",
            )
            .unwrap(),
        )]);

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let mut graph = NativeSynchronousGraph::link_prepared(
                &runtime, &plan, &source_id, configs, &entries,
            )
            .unwrap();
            graph.evaluate().unwrap();
            assert_eq!(graph.namespace_json(&source_id).unwrap(), r#"{"value":42}"#);
            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
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
            let verified = verify_test_artifact(&artifact);
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let retained_context = context.clone();
            let factory = runtime
                .compile_verified_factory(verified, 0, None, 1, "entry.mjs")
                .unwrap();
            let mut record = factory.create_record(&context, &source_id).unwrap();
            record.declare_export("value").unwrap();
            record
                .instantiate("synthetic:module-runner-test/entry", true)
                .unwrap();
            record.run_declare().unwrap();
            let tdz = record.namespace_json().unwrap_err().to_string();
            assert!(
                tdz.contains("before initialization"),
                "namespace getter must preserve TDZ: {tdz}"
            );
            assert_eq!(
                record.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(record.namespace_json().unwrap(), r#"{"value":42}"#);
            drop(record);
            drop(factory);
            drop(retained_context);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn synchronous_graph_links_every_record_before_dependency_first_evaluation() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "driver-target").unwrap();
            let reexport_id = SourceId::synthetic("module-runner-test", "driver-reexport").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "driver-entry").unwrap();
            let target = test_artifact_with_factory(
                target_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { $export('value', 42); } }; }",
                &["value"],
            );
            let reexport = test_graph_artifact(
                reexport_id.clone(),
                "function () { return { declare: function () {}, execute: function () {} }; }",
                vec![StaticEdgeV1::ReExportNamed {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    imported: NonEmptyString::new("value").unwrap(),
                    exported: NonEmptyString::new("answer").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Indirect {
                    exported: NonEmptyString::new("answer").unwrap(),
                    specifier: NonEmptyString::new("./target").unwrap(),
                    imported: NonEmptyString::new("value").unwrap(),
                }],
            );
            let entry = test_graph_artifact(
                entry_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { $export('observed', context.importValue('./reexport', 'answer')); } }; }",
                vec![StaticEdgeV1::Named {
                    specifier: NonEmptyString::new("./reexport").unwrap(),
                    imported: NonEmptyString::new("answer").unwrap(),
                    local: NonEmptyString::new("answer").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("observed").unwrap(),
                    local: NonEmptyString::new("observed").unwrap(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&target), BTreeMap::new()),
                (
                    verify_test_artifact(&reexport),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./reexport".into(), reexport_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        target_id.clone(),
                        config(target_id.clone(), "driver-target"),
                    ),
                    (
                        reexport_id.clone(),
                        config(reexport_id.clone(), "driver-reexport"),
                    ),
                    (entry_id.clone(), config(entry_id.clone(), "driver-entry")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.entry(), &entry_id);
            assert!(graph
                .namespace_json(&entry_id)
                .unwrap_err()
                .to_string()
                .contains("before initialization"));
            graph.evaluate().unwrap();
            graph.evaluate().unwrap();
            assert_eq!(
                graph.namespace_json(&reexport_id).unwrap(),
                r#"{"answer":42}"#
            );
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"observed":42}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn asynchronous_graph_suspends_dependencies_and_makes_rejection_sticky() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let dependency_id =
                SourceId::synthetic("module-runner-test", "async-dependency").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "async-entry").unwrap();
            let dependency = asynchronous_artifact(
                test_artifact_with_factory(
                    dependency_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return Promise.resolve(42).then(function (value) { $export('value', value); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let entry = test_graph_artifact(
                entry_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { $export('observed', context.importValue('./dependency', 'value')); } }; }",
                vec![StaticEdgeV1::Named {
                    specifier: NonEmptyString::new("./dependency").unwrap(),
                    imported: NonEmptyString::new("value").unwrap(),
                    local: NonEmptyString::new("value").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("observed").unwrap(),
                    local: NonEmptyString::new("observed").unwrap(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&dependency), BTreeMap::new()),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./dependency".into(), dependency_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        dependency_id.clone(),
                        config(dependency_id.clone(), "async-dependency"),
                    ),
                    (entry_id.clone(), config(entry_id.clone(), "async-entry")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert!(graph.is_suspended());
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"observed":42}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);

            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let rejection_id = SourceId::synthetic("module-runner-test", "async-reject").unwrap();
            let rejection = asynchronous_artifact(
                test_artifact_with_factory(
                    rejection_id.clone(),
                    "function () { return { declare: function () {}, execute: function () { return Promise.reject(new Error('tla boom')); } }; }",
                    &[],
                ),
                Vec::new(),
            );
            let rejection_plan =
                SynchronousGraphPlan::new([(verify_test_artifact(&rejection), BTreeMap::new())])
                    .unwrap();
            let mut rejection_graph = NativeAsynchronousGraph::link(
                &runtime,
                &rejection_plan,
                &rejection_id,
                BTreeMap::from([(
                    rejection_id.clone(),
                    config(rejection_id.clone(), "async-reject"),
                )]),
            )
            .unwrap();
            assert_eq!(rejection_graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            let first = rejection_graph.poll().unwrap_err().to_string();
            let second = rejection_graph.poll().unwrap_err().to_string();
            assert!(first.contains("tla boom"), "unexpected rejection: {first}");
            assert_eq!(second, first);

            drop(rejection_graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn asynchronous_scc_starts_every_peer_before_waiting() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "async-scc-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "async-scc-b").unwrap();
            let a = test_graph_artifact(
                a_id.clone(),
                "function () { return { declare: function () {}, execute: function () { globalThis.finishAsyncSccB(); } }; }",
                vec![StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new("./b").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                Vec::new(),
            );
            let b = asynchronous_artifact(
                test_graph_artifact(
                    b_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return new Promise(function (resolve) { globalThis.finishAsyncSccB = resolve; }).then(function () { $export('settled', true); }); } }; }",
                    vec![StaticEdgeV1::SideEffect {
                        specifier: NonEmptyString::new("./a").unwrap(),
                        attributes: ImportAttributes::default(),
                    }],
                    vec![ExportDescriptorV1::Local {
                        exported: NonEmptyString::new("settled").unwrap(),
                        local: NonEmptyString::new("settled").unwrap(),
                    }],
                ),
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&a),
                    BTreeMap::from([("./b".into(), b_id.clone())]),
                ),
                (
                    verify_test_artifact(&b),
                    BTreeMap::from([("./a".into(), a_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &a_id,
                BTreeMap::from([
                    (a_id.clone(), config(a_id.clone(), "async-scc-a")),
                    (b_id.clone(), config(b_id.clone(), "async-scc-b")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.schedule().sccs.len(), 1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(graph.namespace_json(&b_id).unwrap(), r#"{"settled":true}"#);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn dynamic_import_returns_fresh_promises_over_one_async_record() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "dynamic-target").unwrap();
            let peer_id = SourceId::synthetic("module-runner-test", "dynamic-peer").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "dynamic-entry").unwrap();
            let target = test_graph_artifact(
                target_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { globalThis.finishDynamicSccPeer(); $export('value', 7); } }; }",
                vec![StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new("./peer").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("value").unwrap(),
                    local: NonEmptyString::new("value").unwrap(),
                }],
            );
            let peer = asynchronous_artifact(
                test_graph_artifact(
                    peer_id.clone(),
                    "function () { return { declare: function () {}, execute: function () { return new Promise(function (resolve) { globalThis.finishDynamicSccPeer = resolve; }); } }; }",
                    vec![StaticEdgeV1::SideEffect {
                        specifier: NonEmptyString::new("./target").unwrap(),
                        attributes: ImportAttributes::default(),
                    }],
                    Vec::new(),
                ),
                Vec::new(),
            );
            let entry = asynchronous_artifact(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { var first = context.dynamicImport('./target'); var second = context.dynamicImport('./target'); $export('fresh', first !== second); return Promise.all([first, second]).then(function (namespaces) { $export('sum', namespaces[0].value + namespaces[1].value); }); } }; }",
                    &["fresh", "sum"],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&target),
                    BTreeMap::from([("./peer".into(), peer_id.clone())]),
                ),
                (
                    verify_test_artifact(&peer),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        target_id.clone(),
                        config(target_id.clone(), "dynamic-target"),
                    ),
                    (peer_id.clone(), config(peer_id.clone(), "dynamic-peer")),
                    (entry_id.clone(), config(entry_id.clone(), "dynamic-entry")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            for tick in 0..4 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"fresh":true,"sum":14}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn mixed_dynamic_static_reentry_rejects_instead_of_deadlocking() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "async-cycle-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "async-cycle-b").unwrap();
            let a = asynchronous_artifact(
                test_artifact_with_factory(
                    a_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { return context.dynamicImport('./b'); } }; }",
                    &[],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./b").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let b = test_graph_artifact(
                b_id.clone(),
                "function () { return { declare: function () {}, execute: function () {} }; }",
                vec![StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new("./a").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&a),
                    BTreeMap::from([("./b".into(), b_id.clone())]),
                ),
                (
                    verify_test_artifact(&b),
                    BTreeMap::from([("./a".into(), a_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &a_id,
                BTreeMap::from([
                    (a_id.clone(), config(a_id.clone(), "async-cycle-a")),
                    (b_id.clone(), config(b_id.clone(), "async-cycle-b")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            let error = graph.poll().unwrap_err().to_string();
            assert!(
                error.contains("ERR_ASYNC_MODULE_CYCLE"),
                "unexpected async cycle error: {error}"
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn commonjs_dynamic_import_returns_an_esm_namespace_promise() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let esm_id = SourceId::synthetic("module-runner-test", "cjs-dynamic-esm").unwrap();
            let cjs_id = SourceId::synthetic("module-runner-test", "cjs-dynamic-owner").unwrap();
            let esm_artifact = asynchronous_artifact(
                test_artifact_with_factory(
                    esm_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return Promise.resolve().then(function () { $export('value', 31); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let esm_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(esm_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let esm_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&esm_artifact),
                    0,
                    None,
                    1,
                    "cjs-dynamic-esm.mjs",
                )
                .unwrap();
            let mut esm = esm_factory.create_record(&esm_context, &esm_id).unwrap();
            esm.declare_export("value").unwrap();
            esm.instantiate("synthetic:module-runner-test/cjs-dynamic-esm", false)
                .unwrap();
            esm.run_declare().unwrap();

            let cjs_artifact = test_commonjs_artifact(
                cjs_id.clone(),
                "function (require, module, exports, __filename, __dirname, dynamicImport) { dynamicImport('./esm').then(function (namespace) { globalThis.cjsDynamicValue = namespace.value; }); }",
                &[],
            );
            let cjs_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(cjs_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let cjs_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&cjs_artifact),
                    0,
                    None,
                    1,
                    "cjs-dynamic-owner.cjs",
                )
                .unwrap();
            let mut cjs = cjs_factory
                .create_commonjs_record(&cjs_context, &cjs_id, "/pkg/owner.cjs", "/pkg")
                .unwrap();
            cjs.link_dynamic_import("./esm", &esm).unwrap();
            cjs.evaluate().unwrap();
            for tick in 0..6 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            let source = "String(globalThis.cjsDynamicValue)";
            let source_url = CString::new("cjs-dynamic-observation.js").unwrap();
            let mut output = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                ),
                0
            );
            assert!(!output.is_null());
            assert_eq!(CStr::from_ptr(output).to_string_lossy(), "31");
            ex_hermes_free_string(output);

            drop(cjs);
            drop(esm);
            drop(cjs_factory);
            drop(cjs_context);
            drop(esm_factory);
            drop(esm_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn commonjs_cycles_publish_early_exports_and_build_snapshot_adapters() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "commonjs-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "commonjs-b").unwrap();
            let a_artifact = test_commonjs_artifact(
                a_id.clone(),
                "function (require, module, exports) { module.exports = { ready: false }; const b = require('./b'); module.exports.fromB = b.sawA; module.exports.ready = true; }",
                &["fromB", "ready"],
            );
            let b_artifact = test_commonjs_artifact(
                b_id.clone(),
                "function (require, module, exports) { exports.sawA = require('./a').ready; }",
                &["sawA"],
            );
            let a_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(a_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let b_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(b_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let a_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&a_artifact),
                    0,
                    None,
                    1,
                    "commonjs-a.cjs",
                )
                .unwrap();
            let b_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&b_artifact),
                    0,
                    None,
                    1,
                    "commonjs-b.cjs",
                )
                .unwrap();
            let mut a = a_factory
                .create_commonjs_record(&a_context, &a_id, "/pkg/a.cjs", "/pkg")
                .unwrap();
            let mut b = b_factory
                .create_commonjs_record(&b_context, &b_id, "/pkg/b.cjs", "/pkg")
                .unwrap();
            a.declare_detected_export("fromB").unwrap();
            a.declare_detected_export("ready").unwrap();
            b.declare_detected_export("sawA").unwrap();
            a.link_require("./b", &b).unwrap();
            b.link_require("./a", &a).unwrap();

            a.evaluate().unwrap();
            b.evaluate().unwrap();
            let a_adapter = a.create_esm_adapter().unwrap();
            let b_adapter = b.create_esm_adapter().unwrap();
            assert_eq!(
                a_adapter.namespace_json().unwrap(),
                r#"{"default":{"ready":true,"fromB":false},"fromB":false,"module.exports":{"ready":true,"fromB":false},"ready":true}"#
            );
            assert_eq!(
                b_adapter.namespace_json().unwrap(),
                r#"{"default":{"sawA":false},"module.exports":{"sawA":false},"sawA":false}"#
            );

            drop(b_adapter);
            drop(a_adapter);
            drop(b);
            drop(a);
            drop(b_factory);
            drop(a_factory);
            drop(b_context);
            drop(a_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn throwing_commonjs_record_is_evicted_and_can_be_recreated() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let source_id = SourceId::synthetic("module-runner-test", "commonjs-throw").unwrap();
            let artifact = test_commonjs_artifact(
                source_id.clone(),
                "function () { throw new Error('cjs boom'); }",
                &["never"],
            );
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&artifact),
                    0,
                    None,
                    1,
                    "commonjs-throw.cjs",
                )
                .unwrap();
            for _ in 0..2 {
                let mut record = factory
                    .create_commonjs_record(&context, &source_id, "/pkg/throw.cjs", "/pkg")
                    .unwrap();
                let error = record.evaluate().unwrap_err().to_string();
                assert!(error.contains("cjs boom"), "unexpected error: {error}");
                assert!(record.create_esm_adapter().is_err());
            }

            drop(factory);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn linked_records_observe_live_binding_updates() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "target").unwrap();
            let importer_id = SourceId::synthetic("module-runner-test", "importer").unwrap();
            let reexport_id = SourceId::synthetic("module-runner-test", "reexport").unwrap();
            let target_artifact = test_artifact_with_factory(
                target_id.clone(),
                "function ($export) { let count; function increment() { $export('count', ++count); } return { declare: function () { $export('increment', increment); }, execute: function () { count = 0; $export('count', count); } }; }",
                &["count", "increment"],
            );
            let importer_artifact = test_artifact_with_factory(
                importer_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { const before = context.importValue('./target', 'count'); context.importValue('./target', 'increment')(); $export('observed', before + ':' + context.importValue('./target', 'count')); } }; }",
                &["observed"],
            );
            let reexport_artifact = test_artifact_with_factory(
                reexport_id.clone(),
                "function () { return { declare: function () {}, execute: function () {} }; }",
                &["count", "target"],
            );
            let target_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let importer_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(importer_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let reexport_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(reexport_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let target_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&target_artifact),
                    0,
                    None,
                    1,
                    "target.mjs",
                )
                .unwrap();
            let importer_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&importer_artifact),
                    0,
                    None,
                    1,
                    "importer.mjs",
                )
                .unwrap();
            let reexport_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&reexport_artifact),
                    0,
                    None,
                    1,
                    "reexport.mjs",
                )
                .unwrap();
            let mut target = target_factory
                .create_record(&target_context, &target_id)
                .unwrap();
            target.declare_export("count").unwrap();
            target.declare_export("increment").unwrap();
            let mut importer = importer_factory
                .create_record(&importer_context, &importer_id)
                .unwrap();
            importer.declare_export("observed").unwrap();
            importer
                .link_import("./target", "count", &target, "count")
                .unwrap();
            importer
                .link_import("./target", "increment", &target, "increment")
                .unwrap();
            let mut reexport = reexport_factory
                .create_record(&reexport_context, &reexport_id)
                .unwrap();
            reexport.declare_export("count").unwrap();
            reexport.declare_export("target").unwrap();
            reexport.link_export("count", &target, "count").unwrap();
            reexport.link_export("target", &target, "*").unwrap();

            target
                .instantiate("synthetic:module-runner-test/target", false)
                .unwrap();
            importer
                .instantiate("synthetic:module-runner-test/importer", true)
                .unwrap();
            reexport
                .instantiate("synthetic:module-runner-test/reexport", false)
                .unwrap();
            target.run_declare().unwrap();
            importer.run_declare().unwrap();
            reexport.run_declare().unwrap();
            assert_eq!(
                target.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(
                importer.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(target.namespace_json().unwrap(), r#"{"count":1}"#);
            assert_eq!(importer.namespace_json().unwrap(), r#"{"observed":"0:1"}"#);
            assert_eq!(
                reexport.namespace_json().unwrap(),
                r#"{"count":1,"target":{"count":1}}"#
            );

            drop(reexport);
            drop(importer);
            drop(target);
            drop(reexport_factory);
            drop(importer_factory);
            drop(target_factory);
            drop(reexport_context);
            drop(importer_context);
            drop(target_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }
}
