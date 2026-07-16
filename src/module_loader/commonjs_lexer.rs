//! Exact host adapter for the pinned `cjs-module-lexer` 2.1.0 detector.
//!
//! The upstream WASM is vendored as reviewed base64 text and executed in a
//! pure-Rust interpreter. This keeps production source loading independent of
//! Node/Bun while preserving the compatibility detector named by LLP 0026.
//! @ref LLP 0026#7-commonjs-interop — named CommonJS exports follow the pinned
//! cjs-module-lexer contract and its version participates in the fingerprint.

use std::cell::RefCell;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use oxc_allocator::Allocator;
use oxc_ast::ast::Expression;
use oxc_parser::Parser;
use oxc_span::SourceType;
use wasmi::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

pub const CJS_MODULE_LEXER_VERSION: &str = "2.1.0";
const CJS_MODULE_LEXER_WASM_BASE64: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/third_party/cjs-module-lexer/lexer.wasm.base64"
));

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonJsLexResult {
    pub exports: Vec<String>,
    pub reexports: Vec<String>,
}

struct CommonJsLexer {
    store: Store<()>,
    memory: Memory,
    allocate_source: TypedFunc<u32, u32>,
    parse: TypedFunc<(u32, u32, u32, u32, u32, u32), u32>,
    error_position: TypedFunc<(), u32>,
    read_export: TypedFunc<(), i32>,
    export_start: TypedFunc<(), u32>,
    export_end: TypedFunc<(), u32>,
    read_reexport: TypedFunc<(), i32>,
    reexport_start: TypedFunc<(), u32>,
    reexport_end: TypedFunc<(), u32>,
    read_unsafe_getter: TypedFunc<(), i32>,
    unsafe_getter_start: TypedFunc<(), u32>,
    unsafe_getter_end: TypedFunc<(), u32>,
}

thread_local! {
    static COMMONJS_LEXER: RefCell<Option<CommonJsLexer>> = const { RefCell::new(None) };
}

pub fn lex_commonjs(source: &str) -> Result<CommonJsLexResult> {
    COMMONJS_LEXER.with(|slot| {
        if slot.borrow().is_none() {
            *slot.borrow_mut() = Some(CommonJsLexer::new()?);
        }
        slot.borrow_mut()
            .as_mut()
            .expect("initialized above")
            .parse(source)
    })
}

impl CommonJsLexer {
    fn new() -> Result<Self> {
        let wasm = STANDARD
            .decode(CJS_MODULE_LEXER_WASM_BASE64.trim())
            .context("decode vendored cjs-module-lexer WASM")?;
        let engine = Engine::default();
        let module =
            Module::new(&engine, &wasm[..]).context("compile vendored cjs-module-lexer WASM")?;
        let mut store = Store::new(&engine, ());
        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .context("instantiate cjs-module-lexer WASM")?
            .start(&mut store)
            .context("start cjs-module-lexer WASM")?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| anyhow!("cjs-module-lexer WASM exports no memory"))?;
        Ok(Self {
            allocate_source: typed(&instance, &store, "sa")?,
            parse: typed(&instance, &store, "parseCJS")?,
            error_position: typed(&instance, &store, "e")?,
            read_export: typed(&instance, &store, "re")?,
            export_start: typed(&instance, &store, "es")?,
            export_end: typed(&instance, &store, "ee")?,
            read_reexport: typed(&instance, &store, "rre")?,
            reexport_start: typed(&instance, &store, "res")?,
            reexport_end: typed(&instance, &store, "ree")?,
            read_unsafe_getter: typed(&instance, &store, "ru")?,
            unsafe_getter_start: typed(&instance, &store, "us")?,
            unsafe_getter_end: typed(&instance, &store, "ue")?,
            store,
            memory,
        })
    }

    fn parse(&mut self, source: &str) -> Result<CommonJsLexResult> {
        let utf16 = source.encode_utf16().collect::<Vec<_>>();
        let source_len = u32::try_from(utf16.len()).context("CommonJS source exceeds u32")?;
        let allocation_len = source_len
            .checked_add(1)
            .ok_or_else(|| anyhow!("CommonJS source allocation overflows"))?;

        // Upstream provisions four bytes per UTF-16 unit beyond the heap base:
        // two for source and two for worst-case analysis records. Growing by
        // that amount beyond current memory is conservative and avoids relying
        // on a toolchain-specific exported heap-base representation.
        let extra_bytes = usize::try_from(allocation_len)?
            .checked_mul(4)
            .ok_or_else(|| anyhow!("CommonJS lexer memory size overflows"))?;
        let additional_pages = extra_bytes.div_ceil(65_536) as u64;
        if additional_pages != 0 {
            self.memory
                .grow(&mut self.store, additional_pages)
                .context("grow cjs-module-lexer memory")?;
        }

        let address = self
            .allocate_source
            .call(&mut self.store, allocation_len)
            .context("allocate cjs-module-lexer source")? as usize;
        let byte_len = usize::try_from(allocation_len)?
            .checked_mul(2)
            .ok_or_else(|| anyhow!("CommonJS UTF-16 byte length overflows"))?;
        let end = address
            .checked_add(byte_len)
            .ok_or_else(|| anyhow!("CommonJS lexer address overflows"))?;
        let memory = self.memory.data_mut(&mut self.store);
        let destination = memory
            .get_mut(address..end)
            .ok_or_else(|| anyhow!("cjs-module-lexer source allocation is out of bounds"))?;
        destination.fill(0);
        for (index, unit) in utf16.iter().enumerate() {
            destination[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }

        let error_code = self
            .parse
            .call(&mut self.store, (address as u32, source_len, 0, 0, 0, 0))
            .context("execute cjs-module-lexer")?;
        if error_code != 0 {
            let position = self
                .error_position
                .call(&mut self.store, ())
                .context("read cjs-module-lexer error position")?;
            if matches!(error_code, 5..=7) {
                bail!("ERR_LEXER_ESM_SYNTAX at UTF-16 offset {position}");
            }
            bail!("cjs-module-lexer parse error {error_code} at UTF-16 offset {position}");
        }

        let mut unsafe_getters = Vec::new();
        while self
            .read_unsafe_getter
            .call(&mut self.store, ())
            .context("iterate cjs-module-lexer unsafe getters")?
            != 0
        {
            if let Some(name) = decode_lexer_slice(&self.read_slice(
                self.unsafe_getter_start,
                self.unsafe_getter_end,
                &utf16,
            )?) {
                unsafe_getters.push(name);
            }
        }

        let mut exports = Vec::new();
        while self
            .read_export
            .call(&mut self.store, ())
            .context("iterate cjs-module-lexer exports")?
            != 0
        {
            if let Some(name) =
                decode_lexer_slice(&self.read_slice(self.export_start, self.export_end, &utf16)?)
            {
                if !unsafe_getters
                    .iter()
                    .any(|unsafe_name| unsafe_name == &name)
                {
                    exports.push(name);
                }
            }
        }

        let mut reexports = Vec::new();
        while self
            .read_reexport
            .call(&mut self.store, ())
            .context("iterate cjs-module-lexer reexports")?
            != 0
        {
            if let Some(specifier) = decode_lexer_slice(&self.read_slice(
                self.reexport_start,
                self.reexport_end,
                &utf16,
            )?) {
                reexports.push(specifier);
            }
        }

        exports.sort();
        exports.dedup();
        reexports.sort();
        reexports.dedup();
        Ok(CommonJsLexResult { exports, reexports })
    }

    fn read_slice(
        &mut self,
        start: TypedFunc<(), u32>,
        end: TypedFunc<(), u32>,
        source: &[u16],
    ) -> Result<String> {
        let start = start.call(&mut self.store, ())? as usize;
        let end = end.call(&mut self.store, ())? as usize;
        let units = source
            .get(start..end)
            .ok_or_else(|| anyhow!("cjs-module-lexer returned an out-of-range slice"))?;
        String::from_utf16(units).context("cjs-module-lexer returned invalid UTF-16")
    }
}

fn typed<Params, Results>(
    instance: &Instance,
    store: &Store<()>,
    name: &str,
) -> Result<TypedFunc<Params, Results>>
where
    Params: wasmi::WasmParams,
    Results: wasmi::WasmResults,
{
    instance
        .get_typed_func(store, name)
        .with_context(|| format!("cjs-module-lexer export {name:?} has an invalid signature"))
}

fn decode_lexer_slice(raw: &str) -> Option<String> {
    if !matches!(raw.as_bytes().first(), Some(b'\'' | b'"')) {
        return Some(raw.to_owned());
    }
    let allocator = Allocator::new();
    let expression = Parser::new(&allocator, raw, SourceType::default().with_module(false))
        .parse_expression()
        .ok()?;
    match expression {
        Expression::StringLiteral(literal) => Some(literal.value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_wasm_detects_exports_reexports_and_unsafe_getters() {
        let result = lex_commonjs(
            r#"
                exports.alpha = 1;
                module.exports['escaped\u002dname'] = 2;
                Object.defineProperty(exports, 'unsafe', { get: function () { return 3; } });
                module.exports = require('./reexport.cjs');
            "#,
        )
        .unwrap();
        assert_eq!(result.exports, ["alpha", "escaped-name"]);
        assert_eq!(result.reexports, ["./reexport.cjs"]);
    }

    #[test]
    fn pinned_wasm_rejects_esm_syntax() {
        let error = lex_commonjs("export const answer = 42;").unwrap_err();
        assert!(error.to_string().contains("ERR_LEXER_ESM_SYNTAX"));
    }
}
