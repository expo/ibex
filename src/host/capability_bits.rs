//! Canonical capability bit assignments shared across the runtime.
//!
//! JavaScript and kernel surfaces are generated from this table via
//! `packages/ibex-devtools/src/scripts/generate-capability-bits.mjs`.
//!
//! @ref LLP 0021#wp0-semantic-contract — this legacy bit plane remains the
//! sole bit-number authority until WP11 removes it; WP0 reconciles every row.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityBitDefinition {
    pub capability: &'static str,
    pub bit: u8,
}

#[rustfmt::skip]
pub const CAPABILITY_BIT_DEFINITIONS: &[CapabilityBitDefinition] = &[
    CapabilityBitDefinition { capability: "network:fetch", bit: 0 },
    CapabilityBitDefinition { capability: "network:connect", bit: 1 },
    CapabilityBitDefinition { capability: "network:listen", bit: 2 },
    CapabilityBitDefinition { capability: "network:local", bit: 3 },
    CapabilityBitDefinition { capability: "fs:read", bit: 4 },
    CapabilityBitDefinition { capability: "fs:write", bit: 5 },
    CapabilityBitDefinition { capability: "fs:list", bit: 6 },
    CapabilityBitDefinition { capability: "fs:watch", bit: 7 },
    CapabilityBitDefinition { capability: "env:read", bit: 8 },
    CapabilityBitDefinition { capability: "process:spawn", bit: 9 },
    CapabilityBitDefinition { capability: "process:signal", bit: 10 },
    CapabilityBitDefinition { capability: "process:cwd", bit: 11 },
    CapabilityBitDefinition { capability: "device:location", bit: 12 },
    CapabilityBitDefinition { capability: "device:location:whenInUse", bit: 13 },
    CapabilityBitDefinition { capability: "device:location:always", bit: 14 },
    CapabilityBitDefinition { capability: "device:location:precise", bit: 15 },
    CapabilityBitDefinition { capability: "device:location:reduced", bit: 16 },
    CapabilityBitDefinition { capability: "device:camera", bit: 17 },
    CapabilityBitDefinition { capability: "device:microphone", bit: 18 },
    CapabilityBitDefinition { capability: "device:photos", bit: 19 },
    CapabilityBitDefinition { capability: "device:photos:read", bit: 20 },
    CapabilityBitDefinition { capability: "device:photos:write", bit: 21 },
    CapabilityBitDefinition { capability: "device:photos:limited", bit: 22 },
    CapabilityBitDefinition { capability: "device:contacts", bit: 23 },
    CapabilityBitDefinition { capability: "device:contacts:read", bit: 24 },
    CapabilityBitDefinition { capability: "device:contacts:write", bit: 25 },
    CapabilityBitDefinition { capability: "device:sensors", bit: 26 },
    CapabilityBitDefinition { capability: "device:motion", bit: 27 },
    CapabilityBitDefinition { capability: "device:bluetooth", bit: 28 },
    CapabilityBitDefinition { capability: "device:bluetooth:scan", bit: 29 },
    CapabilityBitDefinition { capability: "device:bluetooth:connect", bit: 30 },
    CapabilityBitDefinition { capability: "device:bluetooth:advertise", bit: 31 },
    CapabilityBitDefinition { capability: "device:biometrics", bit: 32 },
    CapabilityBitDefinition { capability: "device:credentials", bit: 33 },
    CapabilityBitDefinition { capability: "device:credentials:read", bit: 34 },
    CapabilityBitDefinition { capability: "device:credentials:write", bit: 35 },
    CapabilityBitDefinition { capability: "device:notifications", bit: 36 },
    CapabilityBitDefinition { capability: "device:calendar", bit: 37 },
    CapabilityBitDefinition { capability: "device:calendar:read", bit: 38 },
    CapabilityBitDefinition { capability: "device:calendar:write", bit: 39 },
    CapabilityBitDefinition { capability: "device:reminders", bit: 40 },
    CapabilityBitDefinition { capability: "device:health", bit: 41 },
    CapabilityBitDefinition { capability: "device:health:read", bit: 42 },
    CapabilityBitDefinition { capability: "device:health:write", bit: 43 },
    CapabilityBitDefinition { capability: "storage:local", bit: 44 },
    CapabilityBitDefinition { capability: "storage:session", bit: 45 },
    CapabilityBitDefinition { capability: "storage:persist", bit: 46 },
    CapabilityBitDefinition { capability: "sqlite:read", bit: 47 },
    CapabilityBitDefinition { capability: "sqlite:write", bit: 48 },
    CapabilityBitDefinition { capability: "clipboard:read", bit: 49 },
    CapabilityBitDefinition { capability: "clipboard:write", bit: 50 },
    CapabilityBitDefinition { capability: "crypto:random", bit: 51 },
    CapabilityBitDefinition { capability: "crypto:subtle", bit: 52 },
    CapabilityBitDefinition { capability: "time:now", bit: 53 },
    CapabilityBitDefinition { capability: "time:highres", bit: 54 },
    CapabilityBitDefinition { capability: "ipc:channel", bit: 55 },
    CapabilityBitDefinition { capability: "network:resolve", bit: 56 },
];

#[cfg(test)]
mod tests {
    use super::CAPABILITY_BIT_DEFINITIONS;
    use std::collections::HashSet;

    #[test]
    fn capability_bits_are_unique_and_fit_in_u64() {
        let mut bits = HashSet::new();
        let mut capabilities = HashSet::new();

        for definition in CAPABILITY_BIT_DEFINITIONS {
            assert!(
                bits.insert(definition.bit),
                "duplicate capability bit {}",
                definition.bit
            );
            assert!(
                capabilities.insert(definition.capability),
                "duplicate capability {}",
                definition.capability
            );
            assert!(
                definition.bit < 64,
                "bit {} does not fit in u64",
                definition.bit
            );
        }
    }

    #[test]
    fn capability_bits_are_sorted() {
        for (expected, definition) in CAPABILITY_BIT_DEFINITIONS.iter().enumerate() {
            assert_eq!(definition.bit, expected as u8);
        }
    }
}
