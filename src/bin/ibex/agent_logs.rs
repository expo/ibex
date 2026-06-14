use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_AGENT_LOG_ENTRIES: usize = 1000;
const DEDUP_WINDOW_MS: u64 = 1000;
const DEFAULT_LOG_LIMIT: usize = 200;
const MAX_LOG_LIMIT: usize = 1000;

type JsonMap = Map<String, Value>;

// The shared agent-API log shape also carries `rootId`/`snapshotId`, but the
// CLI runtime has no renderer roots or snapshots, so nothing here ever
// populates them. App hosts keep those fields in their own stores.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentLogEntry {
    entry_id: String,
    timestamp: u64,
    source: String,
    level: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component_stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<JsonMap>,
    count: u32,
    first_timestamp: u64,
    last_timestamp: u64,
}

#[derive(Clone, Debug)]
struct AgentLogInput {
    source: &'static str,
    level: &'static str,
    message: String,
    stack: Option<String>,
    component_stack: Option<String>,
    context: Option<JsonMap>,
    timestamp: u64,
}

#[derive(Default)]
struct AgentLogStore {
    entries: VecDeque<AgentLogEntry>,
    next_entry_ids: HashMap<&'static str, u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogCursorValue {
    entry_id: String,
    last_timestamp: u64,
}

// A `rootId` filter in incoming query JSON is ignored (serde drops unknown
// fields): no CLI entry carries a root, so the filter is inapplicable here.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct HostLogsQuery {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    levels: Vec<String>,
    #[serde(default)]
    cursor: HashMap<String, LogCursorValue>,
    limit: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostLogsResult {
    entries: Vec<AgentLogEntry>,
    sources_available: Vec<&'static str>,
}

fn log_store() -> &'static Mutex<AgentLogStore> {
    static STORE: OnceLock<Mutex<AgentLogStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(AgentLogStore::default()))
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn compare_entry_ids(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<u64>(), right.parse::<u64>()) {
        (Ok(left_id), Ok(right_id)) => left_id.cmp(&right_id),
        _ => left.cmp(right),
    }
}

fn can_collapse(previous: &AgentLogEntry, next: &AgentLogInput) -> bool {
    next.timestamp.saturating_sub(previous.last_timestamp) <= DEDUP_WINDOW_MS
        && previous.source == next.source
        && previous.level == next.level
        && previous.message == next.message
        && previous.stack == next.stack
        && previous.component_stack == next.component_stack
}

fn insert_log(input: AgentLogInput) {
    let mut store = match log_store().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(previous) = store.entries.back_mut() {
        if can_collapse(previous, &input) {
            previous.count = previous.count.saturating_add(1);
            previous.timestamp = input.timestamp;
            previous.last_timestamp = input.timestamp;
            if input.context.is_some() {
                previous.context = input.context;
            }
            return;
        }
    }

    let next_entry_id = {
        let counter = store.next_entry_ids.entry(input.source).or_insert(1);
        let current = *counter;
        *counter = counter.saturating_add(1);
        current
    };

    store.entries.push_back(AgentLogEntry {
        entry_id: next_entry_id.to_string(),
        timestamp: input.timestamp,
        source: input.source.to_string(),
        level: input.level.to_string(),
        message: input.message,
        stack: input.stack,
        component_stack: input.component_stack,
        context: input.context,
        count: 1,
        first_timestamp: input.timestamp,
        last_timestamp: input.timestamp,
    });

    while store.entries.len() > MAX_AGENT_LOG_ENTRIES {
        store.entries.pop_front();
    }
}

fn normalize_sources(sources: &[String]) -> Vec<&'static str> {
    let mut normalized = Vec::new();
    for source in sources {
        match source.as_str() {
            "bundler" if !normalized.contains(&"bundler") => normalized.push("bundler"),
            "host" if !normalized.contains(&"host") => normalized.push("host"),
            _ => {}
        }
    }
    if normalized.is_empty() {
        vec!["bundler", "host"]
    } else {
        normalized
    }
}

fn normalize_levels(levels: &[String]) -> Vec<&'static str> {
    let mut normalized = Vec::new();
    for level in levels {
        match level.as_str() {
            "debug" if !normalized.contains(&"debug") => normalized.push("debug"),
            "info" if !normalized.contains(&"info") => normalized.push("info"),
            "warn" if !normalized.contains(&"warn") => normalized.push("warn"),
            "error" if !normalized.contains(&"error") => normalized.push("error"),
            _ => {}
        }
    }
    if normalized.is_empty() {
        vec!["warn", "error"]
    } else {
        normalized
    }
}

fn entry_is_after_cursor(entry: &AgentLogEntry, cursor: Option<&LogCursorValue>) -> bool {
    let Some(cursor) = cursor else {
        return true;
    };

    if entry.entry_id == cursor.entry_id {
        return entry.last_timestamp > cursor.last_timestamp;
    }

    compare_entry_ids(&entry.entry_id, &cursor.entry_id).is_gt()
}

pub fn record_bundler_log(
    level: &'static str,
    message: impl Into<String>,
    context: Option<JsonMap>,
) {
    insert_log(AgentLogInput {
        source: "bundler",
        level,
        message: message.into(),
        stack: None,
        component_stack: None,
        context,
        timestamp: current_timestamp_ms(),
    });
}

pub fn handle_host_call(operation: &str, args_json: &str) -> Result<String, String> {
    match operation {
        // The CLI runtime has no renderer surface to capture. Say so in a
        // structured payload; callers that probe `result.data` keep degrading
        // gracefully.
        "agent.captureScreenshot" => {
            Ok(r#"{"error":"screenshot capture is not available in the CLI runtime"}"#.to_string())
        }
        "agent.queryLogs" => query_logs(args_json),
        _ => Err(format!("Unknown host call: {operation}")),
    }
}

fn query_logs(args_json: &str) -> Result<String, String> {
    let query: HostLogsQuery = serde_json::from_str(args_json)
        .map_err(|error| format!("Invalid agent.queryLogs args: {error}"))?;
    let sources = normalize_sources(&query.sources);
    let levels = normalize_levels(&query.levels);
    let limit = query.limit.unwrap_or(DEFAULT_LOG_LIMIT).min(MAX_LOG_LIMIT);

    let store = match log_store().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let mut entries = store
        .entries
        .iter()
        .filter(|entry| sources.iter().any(|source| *source == entry.source))
        .filter(|entry| levels.iter().any(|level| *level == entry.level))
        .filter(|entry| entry_is_after_cursor(entry, query.cursor.get(&entry.source)))
        .cloned()
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| compare_entry_ids(&left.entry_id, &right.entry_id))
    });
    entries.truncate(limit);

    serde_json::to_string(&HostLogsResult {
        entries,
        sources_available: vec!["bundler", "host"],
    })
    .map_err(|error| format!("Failed to serialize agent.queryLogs response: {error}"))
}

#[cfg(test)]
pub fn reset_for_tests() {
    let mut store = match log_store().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    store.entries.clear();
    store.next_entry_ids.clear();
}

#[cfg(test)]
mod tests {
    use super::{handle_host_call, record_bundler_log, reset_for_tests};
    use serde_json::{json, Map, Value};

    #[test]
    fn capture_screenshot_reports_structured_error() {
        let response = handle_host_call("agent.captureScreenshot", "{}").expect("host call ok");
        let json = serde_json::from_str::<Value>(&response).expect("parse response");
        assert_eq!(
            json["error"],
            json!("screenshot capture is not available in the CLI runtime")
        );
        assert!(json.get("data").is_none());
    }

    #[test]
    fn query_logs_collapses_consecutive_duplicates() {
        reset_for_tests();

        let mut context = Map::new();
        context.insert("phase".to_string(), Value::String("build".to_string()));

        record_bundler_log("error", "Build failed", Some(context.clone()));
        record_bundler_log("error", "Build failed", Some(context));

        let response = handle_host_call("agent.queryLogs", "{}").expect("query logs");
        let json = serde_json::from_str::<Value>(&response).expect("parse response");
        let entries = json["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["count"], json!(2));
        assert_eq!(entries[0]["source"], json!("bundler"));
    }
}
