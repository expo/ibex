#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolListingFormat {
    Nm { strip_leading_underscore: bool },
    DumpbinExports,
}

pub const STRUCTURED_ASYNC_PROVENANCE_SYMBOLS: &[&str] = &[
    "ex_hermes_vm_current_job_scheduler_principal",
    "ex_hermes_vm_current_job_identity",
    "ex_hermes_vm_current_job_associated_evaluation",
    "ex_hermes_vm_set_job_associated_evaluation",
    "ex_hermes_vm_set_embedder_job_scheduler_principal",
    "ex_hermes_vm_take_failed_job_context",
];

pub const JOB_CONSTRAINED_PRINCIPAL_SYMBOLS: &[&str] = &[
    "ex_hermes_vm_set_embedder_job_constrained_principals",
    "ex_hermes_vm_has_active_job_constrained_principals",
];

fn is_hex_field(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn nm_defined_function_name(line: &str, strip_leading_underscore: bool) -> Option<&str> {
    let mut fields = line.split_whitespace().rev();
    let name = fields.next()?;
    if fields.next()? != "T" || !is_hex_field(fields.next()?) {
        return None;
    }
    if strip_leading_underscore {
        name.strip_prefix('_')
    } else {
        Some(name)
    }
}

fn dumpbin_export_name(line: &str) -> Option<&str> {
    let mut fields = line.split_whitespace();
    fields.next()?.parse::<u32>().ok()?;
    if !is_hex_field(fields.next()?) || !is_hex_field(fields.next()?) {
        return None;
    }
    fields.next()
}

fn defined_symbol_name(format: SymbolListingFormat, line: &str) -> Option<&str> {
    match format {
        SymbolListingFormat::Nm {
            strip_leading_underscore,
        } => nm_defined_function_name(line, strip_leading_underscore),
        SymbolListingFormat::DumpbinExports => dumpbin_export_name(line),
    }
}

pub fn has_exact_defined_symbols(
    format: SymbolListingFormat,
    command_succeeded: bool,
    output: &[u8],
    required: &[&str],
) -> bool {
    if !command_succeeded {
        return false;
    }
    let output = String::from_utf8_lossy(output);
    required.iter().all(|required_symbol| {
        output
            .lines()
            .filter_map(|line| defined_symbol_name(format, line))
            .any(|defined| defined == *required_symbol)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: &[&str] = &[
        "ex_hermes_vm_set_embedder_job_constrained_principals",
        "ex_hermes_vm_has_active_job_constrained_principals",
    ];

    #[test]
    fn accepts_exact_nm_defined_function_symbols() {
        let output = b"\
0000000000000100 T ex_hermes_vm_set_embedder_job_constrained_principals\n\
0000000000000200 T ex_hermes_vm_has_active_job_constrained_principals\n\
0000000000000300 T unrelated\n";
        assert!(has_exact_defined_symbols(
            SymbolListingFormat::Nm {
                strip_leading_underscore: false,
            },
            true,
            output,
            REQUIRED,
        ));
    }

    #[test]
    fn rejects_nm_undefined_only_symbols() {
        let output = b"\
0000000000000100 T ex_hermes_vm_set_embedder_job_constrained_principals\n\
                 U ex_hermes_vm_has_active_job_constrained_principals\n";
        assert!(!has_exact_defined_symbols(
            SymbolListingFormat::Nm {
                strip_leading_underscore: false,
            },
            true,
            output,
            REQUIRED,
        ));
    }

    #[test]
    fn rejects_nm_prefix_and_suffix_collisions() {
        let output = b"\
0000000000000100 T ex_hermes_vm_set_embedder_job_constrained_principals\n\
0000000000000200 T prefix_ex_hermes_vm_has_active_job_constrained_principals\n\
0000000000000300 T ex_hermes_vm_has_active_job_constrained_principals_v2\n";
        assert!(!has_exact_defined_symbols(
            SymbolListingFormat::Nm {
                strip_leading_underscore: false,
            },
            true,
            output,
            REQUIRED,
        ));
    }

    #[test]
    fn accepts_one_mach_o_c_symbol_underscore_only() {
        let output = b"\
0000000000000100 T _ex_hermes_vm_set_embedder_job_constrained_principals\n\
0000000000000200 T _ex_hermes_vm_has_active_job_constrained_principals\n";
        assert!(has_exact_defined_symbols(
            SymbolListingFormat::Nm {
                strip_leading_underscore: true,
            },
            true,
            output,
            REQUIRED,
        ));
        assert!(!has_exact_defined_symbols(
            SymbolListingFormat::Nm {
                strip_leading_underscore: false,
            },
            true,
            output,
            REQUIRED,
        ));
    }

    #[test]
    fn parses_exact_dumpbin_export_names() {
        let output = b"\
    ordinal hint RVA      name\n\
          1    0 00001000 ex_hermes_vm_set_embedder_job_constrained_principals\n\
          2    1 00002000 ex_hermes_vm_has_active_job_constrained_principals\n";
        assert!(has_exact_defined_symbols(
            SymbolListingFormat::DumpbinExports,
            true,
            output,
            REQUIRED,
        ));

        let collision = b"\
          1    0 00001000 ex_hermes_vm_set_embedder_job_constrained_principals\n\
          2    1 00002000 ex_hermes_vm_has_active_job_constrained_principals_v2\n";
        assert!(!has_exact_defined_symbols(
            SymbolListingFormat::DumpbinExports,
            true,
            collision,
            REQUIRED,
        ));
    }

    #[test]
    fn tool_failure_is_always_fail_closed() {
        let output = b"\
0000000000000100 T ex_hermes_vm_set_embedder_job_constrained_principals\n\
0000000000000200 T ex_hermes_vm_has_active_job_constrained_principals\n";
        assert!(!has_exact_defined_symbols(
            SymbolListingFormat::Nm {
                strip_leading_underscore: false,
            },
            false,
            output,
            REQUIRED,
        ));
    }

    #[test]
    fn carrier_symbols_do_not_gate_legacy_structured_async_provenance() {
        let legacy_only = b"\
0000000000000100 T ex_hermes_vm_current_job_scheduler_principal\n\
0000000000000200 T ex_hermes_vm_current_job_identity\n\
0000000000000300 T ex_hermes_vm_current_job_associated_evaluation\n\
0000000000000400 T ex_hermes_vm_set_job_associated_evaluation\n\
0000000000000500 T ex_hermes_vm_set_embedder_job_scheduler_principal\n\
0000000000000600 T ex_hermes_vm_take_failed_job_context\n";
        let format = SymbolListingFormat::Nm {
            strip_leading_underscore: false,
        };
        assert!(has_exact_defined_symbols(
            format,
            true,
            legacy_only,
            STRUCTURED_ASYNC_PROVENANCE_SYMBOLS,
        ));
        assert!(!has_exact_defined_symbols(
            format,
            true,
            legacy_only,
            JOB_CONSTRAINED_PRINCIPAL_SYMBOLS,
        ));
    }
}
