// Test-only isolated loaded-engine executor for the exact effect-classified builtin
// output tranche.  The executor reads only an authored operation plan; it has
// no path to output dispositions or reviewed expectations.
//
// @ref LLP 0022#7-capabilities-principals-and-affordance-parity
// @ref LLP 0023#6-path-bearing-observables
// @ref LLP 0024#9-asynchronous-failures

use super::*;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PLAN_SCHEMA: &str = "ibex/capsec-builtin-effects-output-plan/2";
const INVOCATION_SCHEMA: &str = "ibex/capsec-builtin-effects-output-invocation/1";
const SOURCE_DESCRIPTOR_KIND: &str = "authored-builtin-effects-output";
const ARTIFACT_SCHEMA: &str = "ibex/capsec-builtin-effects-output-artifact/2";
const TIMEOUT_MILLISECONDS: u64 = 1_000;
const OUTPUT_HARNESS: &str = include_str!("capsec_builtin_effects_output_invocation.js");
const OUTPUT_SETUP_HARNESS: &str = include_str!("capsec_builtin_effects_output_setup.js");
const OUTPUT_CLEANUP_HARNESS: &str = include_str!("capsec_builtin_effects_output_cleanup.js");

fn tagged_jcs_digest(value: &Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("builtin effects descriptor must have canonical JSON bytes");
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn invocation(row: &Value) -> &Value {
    assert_eq!(row["probe"]["kind"], "loaded-engine-return-record");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let outer = &row["probe"]["sourceDescriptor"];
    assert_eq!(outer["kind"], SOURCE_DESCRIPTOR_KIND);
    assert_eq!(
        row["probe"]["sourceDescriptorDigest"],
        tagged_jcs_digest(outer)
    );
    let invocation = &outer["invocation"];
    assert_eq!(invocation["invocationSchema"], INVOCATION_SCHEMA);
    assert_eq!(invocation["kind"], "builtin-effects-output");
    assert_eq!(invocation["coverageEdgeId"], row["key"]["surfaceId"]);
    assert_eq!(invocation["coverageClassification"], "effects");
    assert_eq!(
        invocation["decisionEvidence"]["kind"],
        "coverage-bound-typed-effects"
    );
    assert_eq!(
        invocation["decisionEvidence"]["carrierEdgeId"],
        invocation["coverageEdgeId"]
    );
    assert!(invocation["decisionEvidence"]["typedRoutes"]
        .as_array()
        .is_some_and(|routes| !routes.is_empty()));
    let setup = &invocation["route"]["setup"];
    if !setup.is_null() {
        assert_eq!(setup["kind"], "source-authored-filesystem-live-fixture");
        assert_eq!(setup["fixtureKey"], invocation["coverageEdgeId"]);
        assert_eq!(
            setup["decisionEvidence"]["carrierEdgeId"],
            invocation["coverageEdgeId"]
        );
        assert!(setup["decisionEvidence"]["typedRoutes"]
            .as_array()
            .is_some_and(|routes| !routes.is_empty()));
        let mut digest_source = setup.clone();
        digest_source
            .as_object_mut()
            .expect("filesystem setup object")
            .remove("setupDigest");
        assert_eq!(setup["setupDigest"], tagged_jcs_digest(&digest_source));
    }
    assert_eq!(
        invocation["sourceDescriptorDigest"],
        tagged_jcs_digest(&invocation["sourceDescriptor"])
    );
    assert_eq!(
        invocation["completion"],
        json!({
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": TIMEOUT_MILLISECONDS,
        })
    );
    invocation
}

fn invocation_script(row: &Value) -> String {
    format!(
        "JSON.stringify(({})({}))",
        OUTPUT_HARNESS.trim(),
        serde_json::to_string(invocation(row)).expect("serialize builtin effects invocation"),
    )
}

fn fixture_setup(row: &Value) -> Option<&Value> {
    let setup = &invocation(row)["route"]["setup"];
    (!setup.is_null()).then_some(setup)
}

fn fixture_setup_script(row: &Value) -> Option<String> {
    fixture_setup(row).map(|setup| {
        format!(
            "JSON.stringify(({})({}))",
            OUTPUT_SETUP_HARNESS.trim(),
            serde_json::to_string(setup).expect("serialize builtin effects fixture setup"),
        )
    })
}

fn fixture_cleanup_script(row: &Value) -> Option<String> {
    fixture_setup(row).map(|setup| {
        format!(
            "JSON.stringify(({})({}))",
            OUTPUT_CLEANUP_HARNESS.trim(),
            serde_json::to_string(setup).expect("serialize builtin effects fixture cleanup"),
        )
    })
}

fn preload_script(module_specifier: &str) -> String {
    format!(
        "(function(){{require({});return 'ibex-builtin-effects-preloaded';}})()",
        serde_json::to_string(module_specifier).expect("serialize builtin module specifier")
    )
}

fn completion_verification_script(token: &str) -> String {
    format!(
        "JSON.stringify((function(){{var token={};var store=globalThis.__ibexBuiltinEffectsOutputCompletions;var record=store&&store[token];if(store)delete store[token];return record||null;}})())",
        serde_json::to_string(token).expect("serialize completion token")
    )
}

async fn drive_to_quiescence(engine: &HermesEngine) -> Result<(), String> {
    tokio::time::timeout(
        std::time::Duration::from_millis(TIMEOUT_MILLISECONDS),
        engine.drive_event_loop(),
    )
    .await
    .map_err(|_| "event loop did not reach the authored one-second bound".to_owned())?
    .map_err(|error| format!("event-loop completion failed: {error:#}"))
}

async fn take_completion_record(
    sweep: &mut AuthenticatedEffectsSweep,
    engine: &HermesEngine,
    token: &str,
) -> Result<Value, String> {
    let encoded = sweep
        .eval_string(engine, &completion_verification_script(token))
        .await
        .map_err(|error| format!("completion verification failed: {error:#}"))?
        .ok_or_else(|| "completion verification returned no record".to_owned())?;
    let completion = serde_json::from_str::<Value>(&encoded)
        .map_err(|error| format!("completion record was invalid JSON: {error}"))?;
    if completion["calls"] != 1 || completion["settled"] != "fulfilled" {
        return Err(format!(
            "completion did not fulfill exactly once: {completion}"
        ));
    }
    Ok(completion)
}

async fn cleanup_live_fixture(
    row: &Value,
    sweep: &mut AuthenticatedEffectsSweep,
    engine: &HermesEngine,
) -> Result<Value, String> {
    let Some(script) = fixture_cleanup_script(row) else {
        return Ok(Value::Null);
    };
    let encoded = sweep
        .eval_string(engine, &script)
        .await
        .map_err(|error| format!("filesystem fixture cleanup evaluation failed: {error:#}"))?
        .ok_or_else(|| "filesystem fixture cleanup returned no result".to_owned())?;
    let result = serde_json::from_str::<Value>(&encoded)
        .map_err(|error| format!("filesystem fixture cleanup returned invalid JSON: {error}"))?;
    drive_to_quiescence(engine).await?;
    if result["kind"] != "fixture-cleanup-completion" || !result["errorCode"].is_null() {
        return Err(format!("filesystem fixture cleanup failed: {result}"));
    }
    if let Some(token) = result["completionToken"].as_str() {
        let _ = take_completion_record(sweep, engine, token).await?;
    }
    Ok(result)
}

struct AuthenticatedEffectsSweep {
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    active_work_units: BTreeMap<u64, AuthenticatedWorkUnitEvent>,
    due_schedules: BTreeSet<u64>,
}

impl AuthenticatedEffectsSweep {
    fn new(host: &crate::host::Host) -> anyhow::Result<Self> {
        let session = host.mint_armed_session_token()?;
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())?;
        Ok(Self {
            session,
            sequence,
            active_work_units: BTreeMap::new(),
            due_schedules: BTreeSet::new(),
        })
    }

    async fn eval_string(
        &mut self,
        engine: &HermesEngine,
        source: &str,
    ) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications(engine)?;
        let request = self
            .sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })?
            .authorize_inline()
            .bind_bytes(source.as_bytes().to_vec())
            .into_request()?;
        let evaluation = engine
            .evaluate_authenticated(&self.session, request)
            .await?;
        self.drain_publications(engine)?;
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                engine
                    .release_undisplayed_value(receipt.expect("value must retain a receipt"))
                    .await?;
                self.drain_publications(engine)?;
                anyhow::ensure!(
                    display.kind == AuthenticatedDisplayKind::String,
                    "builtin effects source returned {:?}, expected string",
                    display.kind
                );
                Ok(Some(serde_json::from_str(&display.text)?))
            }
            AuthenticatedEvaluation::Throw(thrown) => {
                anyhow::bail!("builtin effects source threw before its envelope: {thrown:?}")
            }
            AuthenticatedEvaluation::Cancelled => {
                anyhow::bail!("builtin effects source was cancelled")
            }
            AuthenticatedEvaluation::Lifecycle(code) => {
                anyhow::bail!("builtin effects source exited with {code}")
            }
        }
    }

    fn drain_publications(&mut self, engine: &HermesEngine) -> anyhow::Result<()> {
        while let Some(event) = engine.next_authenticated_work_unit()? {
            match event.phase {
                AuthenticatedWorkUnitPhase::Due => {
                    anyhow::ensure!(
                        event.kind == AuthenticatedWorkUnitKind::Timer
                            && event.target_id == 0
                            && event.scheduling_id != 0,
                        "malformed Due identities"
                    );
                    anyhow::ensure!(
                        self.due_schedules.insert(event.scheduling_id),
                        "duplicated Due {}",
                        event.scheduling_id
                    );
                }
                AuthenticatedWorkUnitPhase::Undue => {
                    anyhow::ensure!(
                        event.kind == AuthenticatedWorkUnitKind::Timer
                            && event.target_id == 0
                            && event.scheduling_id != 0,
                        "malformed Undue identities"
                    );
                    anyhow::ensure!(
                        self.due_schedules.remove(&event.scheduling_id),
                        "unknown Undue {}",
                        event.scheduling_id
                    );
                }
                AuthenticatedWorkUnitPhase::Begin => {
                    if event.kind == AuthenticatedWorkUnitKind::Timer && event.scheduling_id != 0 {
                        self.due_schedules.remove(&event.scheduling_id);
                    }
                    anyhow::ensure!(
                        self.active_work_units
                            .insert(event.target_id, event)
                            .is_none(),
                        "duplicated Begin"
                    );
                }
                AuthenticatedWorkUnitPhase::Suspended => {
                    let begin = self
                        .active_work_units
                        .get(&event.target_id)
                        .ok_or_else(|| anyhow::anyhow!("Suspended without Begin"))?;
                    anyhow::ensure!(
                        begin.kind == event.kind && begin.scheduling_id == event.scheduling_id,
                        "changed suspended identity"
                    );
                }
                AuthenticatedWorkUnitPhase::End => {
                    let begin = self
                        .active_work_units
                        .remove(&event.target_id)
                        .ok_or_else(|| anyhow::anyhow!("End without Begin"))?;
                    anyhow::ensure!(
                        begin.kind == event.kind && begin.scheduling_id == event.scheduling_id,
                        "changed ended identity"
                    );
                }
            }
        }
        anyhow::ensure!(
            self.active_work_units.is_empty(),
            "active work units remain"
        );
        if let Some(event) = engine.next_authenticated_cancellation()? {
            anyhow::bail!("unexpected cancellation for {}", event.target_id);
        }
        Ok(())
    }

    fn finish(&mut self, engine: &HermesEngine) -> anyhow::Result<()> {
        self.drain_publications(engine)?;
        anyhow::ensure!(
            self.due_schedules.is_empty(),
            "retained due schedules {:?}",
            self.due_schedules
        );
        Ok(())
    }
}

struct PrivateLoopbackFixture {
    tcp_port: u16,
    udp_port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    _udp: std::net::UdpSocket,
}

impl PrivateLoopbackFixture {
    fn new() -> anyhow::Result<Self> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let tcp_port = listener.local_addr()?.port();
        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        udp.set_nonblocking(true)?;
        let udp_port = udp.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(20)));
                        let mut buffer = [0u8; 512];
                        let _ = stream.read(&mut buffer);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            tcp_port,
            udp_port,
            stop,
            thread: Some(thread),
            _udp: udp,
        })
    }
}

impl Drop for PrivateLoopbackFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn project_path_tree(cap: &str) -> Value {
    json!({
        "cap": cap,
        "resource": {
            "kind": "path-tree",
            "path": {
                "root": "project",
                "components": [{"encoding": "utf8", "value": "fixtures"}],
            }
        }
    })
}

fn network_connect(transport: &str, port: u16) -> Value {
    json!({
        "cap": "network:connect",
        "resource": {
            "kind": "connect-endpoint",
            "transport": transport,
            "host": {"kind": "ip", "address": "127.0.0.1"},
            "port": {"kind": "exact", "value": port},
            "peerClasses": ["loopback"],
            "route": {"kind": "direct"},
        }
    })
}

fn network_listen(transport: &str) -> Value {
    json!({
        "cap": "network:listen",
        "resource": {
            "kind": "listen-inet",
            "transport": transport,
            "bind": {"kind": "loopback"},
            "port": {"kind": "ephemeral"},
            "dualStack": false,
            "peerClasses": ["loopback"],
        }
    })
}

fn sys_read(name: &str) -> Value {
    json!({"cap": "sys:read", "resource": {"kind": "system-info", "name": name}})
}

fn env_read(name: &str) -> Value {
    json!({
        "cap": "env:read",
        "resource": {
            "kind": "environment-name",
            "target": "broker-base",
            "name": name,
        }
    })
}

fn stdio(cap: &str, stream: &str, source_kind: &str, identity: &str) -> Value {
    json!({
        "cap": cap,
        "resource": {
            "kind": "stdio",
            "stream": stream,
            "source": {"kind": source_kind, "identity": identity},
        }
    })
}

fn family_floors(family: &str, loopback: &PrivateLoopbackFixture) -> Vec<Value> {
    let mut floors = Vec::new();
    match family {
        "node_http" | "node_net" | "node_http2" => {
            floors.push(network_connect("tcp", loopback.tcp_port));
            floors.push(network_listen("tcp"));
        }
        "node_tls" | "node_https" => {
            floors.push(network_connect("tls", loopback.tcp_port));
            if family == "node_tls" {
                floors.push(network_listen("tcp"));
            }
        }
        "ws" => {
            floors.push(network_connect("ws", loopback.tcp_port));
            floors.push(network_listen("tcp"));
        }
        "node_dgram" => {
            floors.push(network_connect("udp", loopback.udp_port));
            floors.push(network_listen("udp"));
        }
        "exact_http" => floors.push(network_listen("tcp")),
        "node_dns" => floors.push(json!({
            "cap": "network:resolve",
            "resource": {
                "kind": "dns-query",
                "name": "localhost",
                "absolute": true,
                "recordTypes": ["A", "AAAA"],
                "resolver": "system",
            }
        })),
        "node_fs" | "node_fs_promises" | "exact_sqlite" => {
            for cap in ["fs:list", "fs:read", "fs:watch", "fs:write"] {
                floors.push(project_path_tree(cap));
            }
        }
        "node_os" => {
            for name in [
                "architecture",
                "cpus",
                "hostname",
                "load-average",
                "memory",
                "network-interfaces",
                "os-release",
                "platform",
                "uptime",
            ] {
                floors.push(sys_read(name));
            }
        }
        "exact_process" => {
            floors.push(sys_read("user"));
            floors.push(project_path_tree("fs:list"));
            floors.push(json!({
                "cap": "path:cwd-mutate",
                "resource": {
                    "kind": "path-exact",
                    "path": {
                        "root": "project",
                        "components": [{"encoding": "utf8", "value": "fixtures"}],
                    }
                }
            }));
        }
        "node_path" => floors.push(json!({
            "cap": "path:cwd-observe",
            "resource": {"kind": "session-state", "name": "cwd"},
        })),
        "node_util" => {
            floors.push(json!({
                "cap": "env:read",
                "resource": {
                    "kind": "environment-name",
                    "target": "broker-base",
                    "name": "NODE_DEBUG",
                }
            }));
            floors.push(stdio(
                "stdio:write",
                "stdout",
                "broker",
                "ibex:console:stdout",
            ));
        }
        "node_readline" | "node_tty" => {
            floors.push(stdio("stdio:read", "stdin", "pipe", "ibex:repl:stdin"));
            floors.push(stdio(
                "stdio:write",
                "stdout",
                "broker",
                "ibex:console:stdout",
            ));
            floors.push(stdio(
                "stdio:raw",
                "stdin",
                "terminal",
                "ibex:terminal:stdin",
            ));
            floors.push(stdio(
                "stdio:query",
                "stdout",
                "terminal",
                "ibex:terminal:stdout",
            ));
            if family == "node_tty" {
                for name in ["COLUMNS", "LINES", "NO_COLOR"] {
                    floors.push(env_read(name));
                }
            }
        }
        "exact_clipboard" => {
            for cap in ["clipboard:read", "clipboard:write"] {
                floors.push(json!({
                    "cap": cap,
                    "resource": {
                        "kind": "clipboard",
                        "selection": "system",
                        "formats": ["text"],
                    }
                }));
            }
        }
        // Process controls intentionally do not spawn a shell or inherit the
        // ambient environment. Row calls receive invalid argument lists and
        // preserve their real validation throws.
        "node_child_process" | "node_cluster" => {}
        other => panic!("unknown builtin effects family {other}"),
    }
    if matches!(
        family,
        "node_dgram" | "node_http" | "node_https" | "node_tls" | "ws"
    ) {
        floors.push(env_read("EXACT_DEBUG_EMIT_LISTENER"));
    }
    floors
}

fn family_control_script(
    family: &str,
    specifier: &str,
    loopback: &PrivateLoopbackFixture,
) -> String {
    let specifier = serde_json::to_string(specifier).unwrap();
    let tcp_port = loopback.tcp_port;
    let udp_port = loopback.udp_port;
    let body = match family {
        "node_http" => "var s=m.createServer(function(q,r){r.end('ok')});s.on('error',noop);s.listen({host:'127.0.0.1',port:0});s.close();".to_owned(),
        "node_net" => format!(
            "var s=m.createServer(noop);s.on('error',noop);s.listen({{host:'127.0.0.1',port:0}});s.close();var q=m.connect({{host:'127.0.0.1',port:{tcp_port}}});q.on('error',noop);q.destroy();"
        ),
        "node_tls" => format!(
            "var s=m.createServer({{}},noop);s.on('error',noop);s.listen({{host:'127.0.0.1',port:0}});s.close();var q=m.connect({{host:'127.0.0.1',port:{tcp_port},rejectUnauthorized:false}});q.on('error',noop);q.destroy();"
        ),
        "node_https" => format!(
            "var q=m.get({{hostname:'127.0.0.1',port:{tcp_port},path:'/',rejectUnauthorized:false}});q.on('error',noop);"
        ),
        "ws" => "var S=m.WebSocketServer||m.Server;var s=new S({host:'127.0.0.1',port:0});s.on('error',noop);s.on('listening',function(){s.close()});".to_owned(),
        "node_http2" => format!(
            "var s=m.createServer();s.on('error',noop);s.listen({{host:'127.0.0.1',port:0}});s.close();var q=m.connect('http://127.0.0.1:{tcp_port}');q.on('error',noop);q.destroy();"
        ),
        "node_dgram" => format!(
            "var s=m.createSocket('udp4');s.on('error',noop);s.bind(0,'127.0.0.1');s.close();var q=m.createSocket('udp4');q.on('error',noop);q.send('x',{udp_port},'127.0.0.1',function(){{q.close()}});"
        ),
        "node_dns" => "m.lookup('localhost',function(){});".to_owned(),
        "exact_http" => "var p=m.serve({hostname:'127.0.0.1',port:0,fetch:function(){return new Response('ok')}});if(p&&typeof p.then==='function')p.then(function(s){if(s&&typeof s.close==='function')return s.close({force:true})},noop);".to_owned(),
        "node_fs" => "m.writeFileSync('/project/fixtures/control.txt','ibex');m.readFileSync('/project/fixtures/control.txt');m.statSync('/project/fixtures/control.txt');".to_owned(),
        "node_fs_promises" => "var p=m.writeFile('/project/fixtures/control.txt','ibex').then(function(){return m.readFile('/project/fixtures/control.txt')});p.then(noop,noop);".to_owned(),
        "exact_sqlite" => "var D=m.Database||m.default||m;var db=new D('/project/fixtures/control.sqlite');if(typeof db.exec==='function')db.exec('CREATE TABLE IF NOT EXISTS t(v TEXT)');if(typeof db.close==='function')db.close();".to_owned(),
        "node_os" => "m.platform();m.arch();m.cpus();m.totalmem();m.hostname();m.uptime();".to_owned(),
        "exact_process" => "m.getuid();".to_owned(),
        "node_path" => "m.toNamespacedPath('fixture.txt');".to_owned(),
        "node_util" => "m.debuglog('IBEX_OUTPUT_SHAPE');m.log('ibex-output-shape');".to_owned(),
        "node_readline" => "var out={write:function(){return true}};m.clearLine(out,0);m.cursorTo(out,0);".to_owned(),
        "node_tty" => "m.isatty(1);".to_owned(),
        "exact_clipboard" => "m.readText();".to_owned(),
        "node_child_process" => "try{m.spawn()}catch(_){}".to_owned(),
        "node_cluster" => "void m.isPrimary;".to_owned(),
        other => panic!("unknown builtin effects control family {other}"),
    };
    format!(
        "JSON.stringify((function(){{var m=require({specifier});var noop=function(){{}};{body}return{{family:{}}};}})())",
        serde_json::to_string(family).unwrap()
    )
}

fn validate_control_typed_decisions(
    observer_id: &str,
    allowed_caps: &BTreeSet<String>,
    typed: &Value,
) -> Result<(), String> {
    let decisions = typed
        .as_array()
        .ok_or_else(|| "typed decision capture was not an array".to_owned())?;
    if decisions.is_empty() {
        return Err("positive control emitted no typed decisions".to_owned());
    }
    for decision in decisions {
        if decision["terminalBranchId"] != observer_id {
            return Err("typed decision escaped its exact observer".to_owned());
        }
        if decision["evidence"]["outcome"] != "allow" {
            return Err(format!("typed decision was not an allow: {decision}"));
        }
        let gates = decision["gates"]
            .as_array()
            .ok_or_else(|| "typed decision gates were not an array".to_owned())?;
        if gates.is_empty()
            || gates.iter().any(|gate| {
                gate["targetCell"] != "complete"
                    || gate["definitionAndEdgePredicatesSatisfied"] != true
            })
        {
            return Err("typed decision traversed an incomplete gate".to_owned());
        }
        let effects = decision["decisionSet"]["effects"]
            .as_array()
            .ok_or_else(|| "typed decision effects were not an array".to_owned())?;
        if effects.is_empty() {
            return Err("typed decision carried no effects".to_owned());
        }
        for effect in effects {
            let cap = effect["cap"]
                .as_str()
                .ok_or_else(|| "typed effect had no capability".to_owned())?;
            if !allowed_caps.contains(cap) {
                return Err(format!(
                    "typed effect {cap} escaped authored bounds {allowed_caps:?}"
                ));
            }
            if effect["effectOwner"] != json!({"kind": "root", "identity": "project-root"}) {
                return Err("typed effect escaped the exact root principal".to_owned());
            }
            if !effect["resource"].is_object() || effect["resource"]["requested"].is_null() {
                return Err("typed effect omitted its exact requested resource".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_bound_typed_decisions(
    row: &Value,
    observer_id: &str,
    typed: &Value,
    binding: &Value,
    expected_kind: &str,
    output_kind: &str,
    allow_no_effect_branch: bool,
) -> Result<Value, String> {
    let decisions = typed
        .as_array()
        .ok_or_else(|| "typed decision capture was not an array".to_owned())?;
    if binding["kind"] != expected_kind
        || binding["carrierEdgeId"] != invocation(row)["coverageEdgeId"]
    {
        return Err("source decision evidence lost its carrier edge".to_owned());
    }
    let no_effect_branch = &binding["selectedNoEffectBranch"];
    if decisions.is_empty() {
        if no_effect_branch.is_null() || !allow_no_effect_branch {
            return Err("effect-classified source operation emitted no typed decisions".to_owned());
        }
        if no_effect_branch["carrierEdgeId"] != invocation(row)["coverageEdgeId"]
            || no_effect_branch["branchId"]
                .as_str()
                .is_none_or(|branch| branch.is_empty())
            || no_effect_branch["conditions"]
                .as_array()
                .is_none_or(|conditions| conditions.is_empty())
        {
            return Err("zero-decision source operation has no exact no-effect branch".to_owned());
        }
        return Ok(json!({
            "kind": "coverage-bound-typed-effects",
            "carrierEdgeId": binding["carrierEdgeId"].clone(),
            "branchId": observer_id,
            "decisions": [],
            "noEffectBranch": no_effect_branch.clone(),
        }));
    }
    if !no_effect_branch.is_null() {
        return Err("source selected a no-effect branch but emitted typed decisions".to_owned());
    }
    let typed_routes = binding["typedRoutes"]
        .as_array()
        .ok_or_else(|| "source decision binding has no typed routes".to_owned())?;
    let routes = typed_routes
        .iter()
        .map(|route| {
            route["coverageEdgeId"]
                .as_str()
                .map(|edge| (edge, route))
                .ok_or_else(|| "source typed route has no coverage edge".to_owned())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if routes.len() != typed_routes.len() {
        return Err("source decision binding duplicated a coverage edge".to_owned());
    }

    let root = json!({"kind": "root", "identity": "project-root"});
    let mut proof_decisions = Vec::with_capacity(decisions.len());
    let mut observed_edge_ids = BTreeSet::new();
    for decision in decisions {
        if decision["terminalBranchId"] != observer_id {
            return Err("typed decision escaped its exact observer branch".to_owned());
        }
        if decision["evidence"]["outcome"] != "allow" {
            return Err(format!("typed decision was not an allow: {decision}"));
        }
        let set = &decision["decisionSet"];
        let stage = set["context"]["stage"]
            .as_str()
            .ok_or_else(|| "typed decision omitted its exact stage".to_owned())?;
        if decision["evidence"]["stage"] != stage
            || decision["evidence"]["operationId"] != set["operationId"]
            || decision["evidence"]["actor"] != set["context"]["actor"]
            || set["context"]["actor"] != root
            || set["context"]["constrainedPrincipals"] != json!([root.clone()])
            || set["combination"] != "conjunction"
        {
            return Err("typed decision lost its exact root/stage/operation binding".to_owned());
        }
        let effects = set["effects"]
            .as_array()
            .ok_or_else(|| "typed decision effects were not an array".to_owned())?;
        let gates = decision["gates"]
            .as_array()
            .ok_or_else(|| "typed decision gates were not an array".to_owned())?;
        if effects.is_empty() || gates.len() != effects.len() {
            return Err("typed decision had no exact effect-to-gate join".to_owned());
        }
        let edge_ids = gates
            .iter()
            .map(|gate| {
                if gate["targetCell"] != "complete"
                    || gate["definitionAndEdgePredicatesSatisfied"] != true
                {
                    return Err("typed decision traversed an incomplete gate".to_owned());
                }
                gate["coverageEdgeId"]
                    .as_str()
                    .filter(|edge| !edge.is_empty())
                    .ok_or_else(|| "typed gate omitted its coverage edge".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if edge_ids.len() != 1 {
            return Err("one typed decision selected multiple coverage edges".to_owned());
        }
        let edge_id = *edge_ids.iter().next().expect("one typed edge");
        observed_edge_ids.insert(edge_id.to_owned());
        if set["atomicityGroup"] != format!("{edge_id}.decision") {
            return Err("typed gate disagreed with its atomicity group".to_owned());
        }
        let route = routes
            .get(edge_id)
            .ok_or_else(|| format!("typed decision used unauthored coverage edge {edge_id}"))?;
        let coverage_actions = route["actionStages"]
            .as_array()
            .ok_or_else(|| "typed route action stages were not an array".to_owned())?;
        let internal_observer_actions = route["internalObserverActionStages"]
            .as_array()
            .ok_or_else(|| {
                "typed route internal observer action stages were not an array".to_owned()
            })?;
        let allowed_actions = coverage_actions
            .iter()
            .chain(internal_observer_actions.iter())
            .filter(|action| {
                action["stages"]
                    .as_array()
                    .is_some_and(|stages| stages.iter().any(|candidate| candidate == stage))
            })
            .map(|action| {
                action["actionId"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "typed route action had no identity".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let actual_actions = effects
            .iter()
            .map(|effect| {
                if effect["effectOwner"] != root
                    || !effect["resource"].is_object()
                    || effect["resource"]["requested"].is_null()
                {
                    return Err("typed effect lost its root owner or requested resource".to_owned());
                }
                effect["cap"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "typed effect had no action identity".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if actual_actions.len() != effects.len()
            || actual_actions.is_empty()
            || !actual_actions.is_subset(&allowed_actions)
        {
            return Err(format!(
                "typed actions at {edge_id}/{stage} drifted: actual={actual_actions:?} allowed={allowed_actions:?}"
            ));
        }
        proof_decisions.push(json!({
            "coverageEdgeId": edge_id,
            "actionIds": actual_actions.into_iter().collect::<Vec<_>>(),
            "stage": stage,
        }));
    }
    let required_edge_ids = binding["requiredDecisionEdgeIds"]
        .as_array()
        .ok_or_else(|| "decision binding has no required edge set".to_owned())?;
    for required in required_edge_ids {
        let required = required
            .as_str()
            .ok_or_else(|| "required decision edge was not a string".to_owned())?;
        if !observed_edge_ids.contains(required) {
            return Err(format!(
                "source operation emitted no decision for required target edge {required}"
            ));
        }
    }
    Ok(json!({
        "kind": output_kind,
        "carrierEdgeId": binding["carrierEdgeId"].clone(),
        "branchId": observer_id,
        "decisions": proof_decisions,
        "noEffectBranch": null,
    }))
}

fn validate_source_typed_decisions(
    row: &Value,
    observer_id: &str,
    typed: &Value,
) -> Result<Value, String> {
    validate_bound_typed_decisions(
        row,
        observer_id,
        typed,
        &invocation(row)["decisionEvidence"],
        "coverage-bound-typed-effects",
        "coverage-bound-typed-effects",
        true,
    )
}

fn validate_fixture_setup_typed_decisions(
    row: &Value,
    observer_id: &str,
    typed: &Value,
) -> Result<Value, String> {
    validate_bound_typed_decisions(
        row,
        observer_id,
        typed,
        &invocation(row)["route"]["setup"]["decisionEvidence"],
        "coverage-bound-fixture-setup-effects",
        "coverage-bound-fixture-setup-effects",
        false,
    )
}

fn validate_target_refusal(family: &str, execution_reason: &str, typed: &Value) -> bool {
    let stable_message = match family {
        "exact_clipboard" => "Exact clipboard not available",
        "node_http2" => {
            "http2.createServer is not supported in this runtime without native HTTP/2 support"
        }
        _ => return false,
    };
    execution_reason.contains(stable_message)
        && typed
            .as_array()
            .is_some_and(|decisions| decisions.is_empty())
}

fn source_completion_is_exercised(raw: &Value) -> bool {
    raw["kind"] == "return"
        && raw["rawValueShape"]
            .as_str()
            .is_some_and(|shape| shape != "throw")
        && raw["value"].is_null()
        && raw["errorCode"].is_null()
}

fn residual(
    row: &Value,
    family: &str,
    code: &str,
    reason: impl AsRef<str>,
    details: Value,
) -> Value {
    json!({
        "key": row["key"].clone(),
        "cohort": invocation(row)["cohort"].clone(),
        "family": family,
        "reasonCode": code,
        "reason": reason.as_ref(),
        "details": details,
    })
}

fn observation(
    row: &Value,
    family: &str,
    raw: Value,
    effect_evidence: Value,
    fixture_setup_evidence: Value,
    fixture_cleanup: Value,
) -> Value {
    json!({
        "key": row["key"].clone(),
        "cohort": invocation(row)["cohort"].clone(),
        "family": family,
        "proof": {
            "kind": "loaded-engine-return-record",
            "fixtureId": row["probe"]["fixtureId"].clone(),
            "sourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"].clone(),
            "recordPath": row["probe"]["recordPath"].clone(),
            "rawValueShape": raw["rawValueShape"].clone(),
            "effectEvidence": effect_evidence,
            "fixtureSetupEvidence": fixture_setup_evidence,
            "fixtureCleanup": fixture_cleanup,
        },
        "raw": raw,
    })
}

fn prepare_filesystem_row_fixture(
    project_root: &std::path::Path,
    row: &Value,
) -> anyhow::Result<()> {
    let source_key = invocation(row)["sourceDescriptor"]["sourceKey"]
        .as_str()
        .expect("builtin effects source family");
    if !matches!(source_key, "node_fs" | "node_fs_promises") {
        return Ok(());
    }
    let edge_id = invocation(row)["coverageEdgeId"]
        .as_str()
        .expect("builtin effects coverage edge");
    anyhow::ensure!(
        edge_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')),
        "filesystem row fixture edge is not one safe path component"
    );
    let root = project_root.join("fixtures").join(edge_id);
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(root.join("directory"))?;
    std::fs::create_dir_all(root.join("empty-directory"))?;
    std::fs::write(
        root.join("input.txt"),
        b"ibex builtin effects row fixture\n",
    )?;
    std::fs::write(
        root.join("directory").join("child.txt"),
        b"ibex builtin effects directory fixture\n",
    )?;
    Ok(())
}

async fn execute_family(
    family: &str,
    rows: &[&Value],
) -> anyhow::Result<(Vec<Value>, Vec<Value>, Value, Value)> {
    let project = tempfile::tempdir()?;
    std::fs::create_dir_all(project.path().join("fixtures"))?;
    std::fs::create_dir_all(project.path().join("node_modules/image-lib"))?;
    std::fs::write(project.path().join("package.json"), b"{\"private\":true}\n")?;
    std::fs::write(
        project.path().join("fixtures/input.txt"),
        b"ibex builtin effects fixture\n",
    )?;
    // macOS exposes the tempfile root through `/var` but descriptor identity
    // reports `/private/var`. Bind the canonical project spelling so the
    // armed synchronous descriptor walk and the snapshot share one exact host
    // coordinate. The public evidence remains `/project/...`.
    // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
    let project_root = std::fs::canonicalize(project.path())?;
    let loopback = PrivateLoopbackFixture::new()?;
    let floors = family_floors(family, &loopback);
    let module_specifiers = rows
        .iter()
        .map(|row| {
            invocation(row)["moduleSpecifier"]
                .as_str()
                .expect("builtin effects module specifier")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let mut imports = module_specifiers.iter().cloned().collect::<BTreeSet<_>>();
    imports.extend(rows.iter().filter_map(|row| {
        fixture_setup(row)?["moduleSpecifier"]
            .as_str()
            .map(str::to_owned)
    }));
    match family {
        "node_https" => {
            imports.extend([
                "http".to_owned(),
                "net".to_owned(),
                "node:http".to_owned(),
                "node:net".to_owned(),
                "node:tls".to_owned(),
                "tls".to_owned(),
            ]);
        }
        "node_http" | "node_tls" | "ws" => {
            imports.insert("node:net".to_owned());
        }
        _ => {}
    }
    let preload_specifiers = imports.clone();
    let imports = imports.into_iter().map(Value::String).collect::<Vec<_>>();
    let (host, digest) = build_armed_test_host_control(
        Some(&project_root),
        false,
        false,
        false,
        floors.clone(),
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
            snapshot["bootstrapCompatibilityModes"] = json!(["bun"]);
            snapshot["principals"][0]["imports"]["builtins"] = Value::Array(imports.clone());
            snapshot["entry"] = json!({
                "kind": "repl",
                "identity": "ibex:repl",
                "mode": "interactive",
            });
        },
    );
    anyhow::ensure!(
        crate::host::abi::install_host(host.clone()) != 0,
        "install Host"
    );
    let reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))?;
    engine.load_runtime().await?;
    let mut sweep = AuthenticatedEffectsSweep::new(&host)?;

    let mut preload_failures = BTreeMap::new();
    for module_specifier in &preload_specifiers {
        let preload = sweep
            .eval_string(&engine, &preload_script(module_specifier))
            .await;
        let reason = match preload {
            Ok(Some(marker)) if marker == "ibex-builtin-effects-preloaded" => {
                drive_to_quiescence(&engine).await.err()
            }
            Ok(value) => Some(format!("module preload returned {value:?}")),
            Err(error) => Some(format!("module preload failed: {error:#}")),
        };
        if let Some(reason) = reason {
            preload_failures.insert(module_specifier.clone(), reason);
        }
    }

    let control_specifier = module_specifiers
        .iter()
        .next()
        .expect("family has a module specifier");
    let control_observer = format!("builtin-effects-positive:{family}");
    let control_started =
        ibex_runtime::host::abi::begin_installed_conformance_observation(&control_observer);
    let control_execution = if control_started {
        sweep
            .eval_string(
                &engine,
                &family_control_script(family, control_specifier, &loopback),
            )
            .await
            .map_err(|error| format!("{error:#}"))
    } else {
        Err("Host refused positive-control observer".to_owned())
    };
    let control_quiescence = drive_to_quiescence(&engine).await;
    let (control_legacy, control_typed) =
        ibex_runtime::host::abi::take_installed_conformance_observations();
    let control_typed = serde_json::to_value(control_typed)?;
    let family_caps = floors
        .iter()
        .filter_map(|floor| floor["cap"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let target_refusal = control_execution
        .as_ref()
        .err()
        .is_some_and(|reason| validate_target_refusal(family, reason, &control_typed));
    let control_validation = if !control_legacy.is_empty() {
        Err(format!(
            "positive control emitted {} legacy decisions",
            control_legacy.len()
        ))
    } else if let Err(reason) = &control_quiescence {
        Err(reason.clone())
    } else if target_refusal {
        Ok(())
    } else if let Err(reason) = &control_execution {
        Err(reason.clone())
    } else if matches!(family, "exact_clipboard" | "node_http2") {
        Err("target-refused control unexpectedly returned normally".to_owned())
    } else {
        validate_control_typed_decisions(&control_observer, &family_caps, &control_typed)
    };
    let control_block = if target_refusal {
        Some((
            "family-positive-control-target-refused",
            "target refused the public family positive control".to_owned(),
        ))
    } else {
        control_validation.as_ref().err().map(|reason| {
            (
                "family-positive-control-failed",
                format!("public family positive control failed: {reason}"),
            )
        })
    };
    let control = json!({
        "family": family,
        "moduleSpecifier": control_specifier,
        "observerId": control_observer,
        "execution": match control_execution { Ok(value) => json!({"ok": true, "value": value}), Err(reason) => json!({"ok": false, "reason": reason}) },
        "quiescence": match control_quiescence { Ok(()) => json!({"ok": true}), Err(reason) => json!({"ok": false, "reason": reason}) },
        "legacyDecisionCount": control_legacy.len(),
        "typedDecisions": control_typed,
        "disposition": if target_refusal { "target-refused" } else { "supported" },
        "validation": match &control_validation { Ok(()) => json!({"ok": true}), Err(reason) => json!({"ok": false, "reason": reason}) },
    });

    let fixture_audit = json!({
        "family": family,
        "projectLogicalRoot": "project",
        "privateFixtureComponents": ["fixtures"],
        "privateLoopback": {
            "host": "127.0.0.1",
            "tcpPort": loopback.tcp_port,
            "udpPort": loopback.udp_port,
        },
        "resolvedStaticFloor": floors,
        "armedSnapshotDigest": digest,
    });

    let mut observed = Vec::new();
    let mut blocked = Vec::new();
    for row in rows {
        if let Some((code, reason)) = &control_block {
            blocked.push(residual(row, family, code, reason, Value::Null));
            continue;
        }
        let module_specifier = invocation(row)["moduleSpecifier"]
            .as_str()
            .expect("builtin effects module specifier");
        if let Some(reason) = preload_failures.get(module_specifier) {
            blocked.push(residual(
                row,
                family,
                "module-preload-failed",
                reason,
                Value::Null,
            ));
            continue;
        }
        if let Err(error) = prepare_filesystem_row_fixture(&project_root, row) {
            blocked.push(residual(
                row,
                family,
                "row-fixture-preparation-failed",
                format!("could not prepare the private filesystem row fixture: {error:#}"),
                Value::Null,
            ));
            continue;
        }
        let fixture_id = row["probe"]["fixtureId"]
            .as_str()
            .expect("builtin effects fixture ID");
        let observer_id = format!("output-shape:{fixture_id}");
        let fixture_setup_evidence = if let Some(setup_script) = fixture_setup_script(row) {
            let setup_observer_id = format!("{observer_id}:fixture-setup");
            if !ibex_runtime::host::abi::begin_installed_conformance_observation(&setup_observer_id)
            {
                blocked.push(residual(
                    row,
                    family,
                    "fixture-setup-observer-installation-refused",
                    "Host refused the exact filesystem fixture setup observer",
                    Value::Null,
                ));
                continue;
            }
            let setup_execution = sweep.eval_string(&engine, &setup_script).await;
            let setup_quiescence = drive_to_quiescence(&engine).await;
            let (setup_legacy, setup_typed) =
                ibex_runtime::host::abi::take_installed_conformance_observations();
            let setup_typed = serde_json::to_value(setup_typed)?;
            let setup_validation = (|| -> Result<(Value, Value), String> {
                if !setup_legacy.is_empty() {
                    return Err(format!(
                        "filesystem fixture setup emitted {} legacy decisions",
                        setup_legacy.len()
                    ));
                }
                setup_quiescence.clone()?;
                let encoded = setup_execution
                    .as_ref()
                    .map_err(|error| format!("filesystem fixture setup failed: {error:#}"))?
                    .as_ref()
                    .ok_or_else(|| "filesystem fixture setup returned no result".to_owned())?;
                let result = serde_json::from_str::<Value>(encoded).map_err(|error| {
                    format!("filesystem fixture setup returned invalid JSON: {error}")
                })?;
                if result["kind"] != "fixture-setup-completion"
                    || result["fixtureKey"] != invocation(row)["route"]["setup"]["fixtureKey"]
                    || !source_completion_is_exercised(&result["rawOutput"])
                {
                    return Err(format!(
                        "filesystem fixture setup did not return normally: {result}"
                    ));
                }
                Ok((
                    validate_fixture_setup_typed_decisions(row, &setup_observer_id, &setup_typed)?,
                    result,
                ))
            })();
            let (evidence, setup_result) = match setup_validation {
                Ok(value) => value,
                Err(reason) => {
                    let _ = cleanup_live_fixture(row, &mut sweep, &engine).await;
                    blocked.push(residual(
                        row,
                        family,
                        "filesystem-live-fixture-setup-failed",
                        reason,
                        json!({
                            "legacyDecisions": setup_legacy,
                            "typedDecisions": setup_typed,
                            "quiescenceError": setup_quiescence.as_ref().err(),
                        }),
                    ));
                    continue;
                }
            };
            if let Some(token) = setup_result["completionToken"].as_str() {
                if let Err(reason) = take_completion_record(&mut sweep, &engine, token).await {
                    let _ = cleanup_live_fixture(row, &mut sweep, &engine).await;
                    blocked.push(residual(
                        row,
                        family,
                        "filesystem-live-fixture-setup-settlement-failed",
                        reason,
                        json!({"setup": setup_result, "typedDecisions": setup_typed}),
                    ));
                    continue;
                }
            }
            evidence
        } else {
            Value::Null
        };
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
            let _ = cleanup_live_fixture(row, &mut sweep, &engine).await;
            blocked.push(residual(
                row,
                family,
                "observer-installation-refused",
                "Host refused the exact row observer",
                Value::Null,
            ));
            continue;
        }
        let execution = sweep.eval_string(&engine, &invocation_script(row)).await;
        let quiescence = drive_to_quiescence(&engine).await;
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        let typed = serde_json::to_value(typed)?;
        let fixture_cleanup = cleanup_live_fixture(row, &mut sweep, &engine).await;
        let fixture_cleanup = match fixture_cleanup {
            Ok(cleanup) => cleanup,
            Err(reason) => {
                blocked.push(residual(
                    row,
                    family,
                    "filesystem-live-fixture-cleanup-failed",
                    reason,
                    json!({"typedDecisions": typed}),
                ));
                continue;
            }
        };
        if !legacy.is_empty() {
            blocked.push(residual(
                row,
                family,
                "legacy-capability-decision-observed",
                format!("source operation emitted {} legacy decisions", legacy.len()),
                json!({"legacyDecisions": legacy, "typedDecisions": typed}),
            ));
            continue;
        }
        let effect_evidence = match validate_source_typed_decisions(row, &observer_id, &typed) {
            Ok(evidence) => evidence,
            Err(reason) => {
                let execution_diagnostic = match &execution {
                    Ok(Some(encoded)) => serde_json::from_str::<Value>(encoded)
                        .unwrap_or_else(|_| json!({"encoded": encoded})),
                    Ok(None) => json!({"kind": "no-result"}),
                    Err(error) => {
                        json!({"kind": "evaluation-error", "error": format!("{error:#}")})
                    }
                };
                blocked.push(residual(
                    row,
                    family,
                    "typed-authority-mismatch",
                    reason,
                    json!({
                        "typedDecisions": typed,
                        "execution": execution_diagnostic,
                        "quiescenceError": quiescence.as_ref().err(),
                    }),
                ));
                continue;
            }
        };
        if let Err(reason) = quiescence {
            blocked.push(residual(
                row,
                family,
                "event-loop-completion-failed",
                reason,
                json!({"typedDecisions": typed}),
            ));
            continue;
        }
        let encoded = match execution {
            Ok(Some(encoded)) => encoded,
            Ok(None) => {
                blocked.push(residual(
                    row,
                    family,
                    "loaded-invocation-no-result",
                    "loaded invocation returned no result",
                    json!({"typedDecisions": typed}),
                ));
                continue;
            }
            Err(error) => {
                blocked.push(residual(
                    row,
                    family,
                    "loaded-invocation-evaluation-failed",
                    format!("{error:#}"),
                    json!({"typedDecisions": typed}),
                ));
                continue;
            }
        };
        let result: Value = match serde_json::from_str(&encoded) {
            Ok(result) => result,
            Err(error) => {
                blocked.push(residual(
                    row,
                    family,
                    "loaded-invocation-invalid-json",
                    error.to_string(),
                    json!({"encoded": encoded, "typedDecisions": typed}),
                ));
                continue;
            }
        };
        if let Some(token) = result["completionToken"].as_str() {
            if let Err(reason) = take_completion_record(&mut sweep, &engine, token).await {
                blocked.push(residual(
                    row,
                    family,
                    "promise-settlement-unproven",
                    reason,
                    json!({"result": result, "typedDecisions": typed}),
                ));
                continue;
            }
        }
        if result["kind"] != "source-completion"
            || result["sourceOperationAttempted"] != true
            || result["cleanupPerformed"] != true
        {
            blocked.push(residual(
                row,
                family,
                "source-operation-or-cleanup-unproven",
                "exact source operation and cleanup were not both proven",
                json!({"result": result, "typedDecisions": typed}),
            ));
            continue;
        }
        if !matches!(
            result["descriptorProof"]["descriptorKind"].as_str(),
            Some("data") | Some("accessor") | Some("module-value")
        ) {
            blocked.push(residual(
                row,
                family,
                "source-descriptor-unproven",
                "loaded property descriptor did not match the authored source",
                json!({"result": result, "typedDecisions": typed}),
            ));
            continue;
        }
        let raw = &result["rawOutput"];
        if !source_completion_is_exercised(raw) {
            blocked.push(residual(
                row,
                family,
                "invalid-source-completion-envelope",
                "exact source operation did not return normally",
                json!({"result": result, "typedDecisions": typed}),
            ));
            continue;
        }
        observed.push(observation(
            row,
            family,
            raw.clone(),
            effect_evidence,
            fixture_setup_evidence,
            fixture_cleanup,
        ));
    }

    if let Err(error) = sweep.finish(&engine) {
        let prior = std::mem::take(&mut observed);
        for prior_observation in prior {
            let key = &prior_observation["key"];
            let row = rows
                .iter()
                .find(|row| row["key"] == *key)
                .expect("find retained-work row");
            blocked.push(residual(
                row,
                family,
                "family-retained-authenticated-work",
                format!("{error:#}"),
                json!({"priorObservation": prior_observation}),
            ));
        }
    }
    drop(sweep);
    drop(engine);
    drop(reset);
    Ok((observed, blocked, control, fixture_audit))
}

struct EffectsBatchExecution {
    observed: Vec<Value>,
    blocked: Vec<Value>,
    controls: Vec<Value>,
    fixture_audits: Vec<Value>,
    family_failures: Vec<Value>,
    family_count: usize,
}

async fn execute_rows_with_diagnostics(rows: &[Value]) -> EffectsBatchExecution {
    let mut by_family = BTreeMap::<String, Vec<&Value>>::new();
    for row in rows {
        by_family
            .entry(
                invocation(row)["sourceDescriptor"]["sourceKey"]
                    .as_str()
                    .expect("builtin effects source family")
                    .to_owned(),
            )
            .or_default()
            .push(row);
    }
    let family_count = by_family.len();
    let mut observed = Vec::new();
    let mut blocked = Vec::new();
    let mut controls = Vec::new();
    let mut fixture_audits = Vec::new();
    let mut family_failures = Vec::new();
    for (family, family_rows) in &by_family {
        match execute_family(family, family_rows).await {
            Ok((mut family_observed, mut family_blocked, control, fixture_audit)) => {
                observed.append(&mut family_observed);
                blocked.append(&mut family_blocked);
                controls.push(control);
                fixture_audits.push(fixture_audit);
            }
            Err(error) => {
                family_failures.push(json!({"family": family, "reason": format!("{error:#}")}));
                for row in family_rows {
                    blocked.push(residual(
                        row,
                        family,
                        "family-executor-failed",
                        format!("{error:#}"),
                        Value::Null,
                    ));
                }
            }
        }
    }
    observed.sort_by_key(|value| serde_json::to_string(&value["key"]).unwrap());
    blocked.sort_by_key(|value| serde_json::to_string(&value["key"]).unwrap());
    EffectsBatchExecution {
        observed,
        blocked,
        controls,
        fixture_audits,
        family_failures,
        family_count,
    }
}

pub(super) fn is_surface(row: &Value) -> bool {
    row["probe"]["kind"] == "loaded-engine-return-record"
        && row["probe"]["sourceDescriptor"]["kind"] == SOURCE_DESCRIPTOR_KIND
}

pub(super) async fn execute_builtin_effects_output_rows(
    rows: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    let execution = execute_rows_with_diagnostics(rows).await;
    let observed = execution
        .observed
        .into_iter()
        .map(|observation| {
            json!({
                "key": observation["key"].clone(),
                "proof": observation["proof"].clone(),
                "raw": observation["raw"].clone(),
            })
        })
        .collect();
    let unexercisable = execution
        .blocked
        .into_iter()
        .map(|blocked| {
            json!({
                "key": blocked["key"].clone(),
                "reason": format!(
                    "{}: {}",
                    blocked["reasonCode"].as_str().unwrap_or("builtin-effects-output-blocked"),
                    blocked["reason"].as_str().unwrap_or("source operation was not proven"),
                ),
            })
        })
        .collect();
    (observed, unexercisable)
}

fn write_artifact(path: &str, value: &Value) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create builtin effects artifact");
    serde_json::to_writer_pretty(&mut file, value).expect("serialize builtin effects artifact");
    file.write_all(b"\n")
        .expect("terminate builtin effects artifact");
    file.sync_all().expect("sync builtin effects artifact");
}

fn validator_fixture_row(no_effect: bool) -> Value {
    let source_descriptor = json!({"kind": "builtin-export"});
    let invocation = json!({
        "invocationSchema": INVOCATION_SCHEMA,
        "kind": "builtin-effects-output",
        "coverageEdgeId": "surface.builtin.fixture",
        "coverageClassification": "effects",
        "sourceDescriptor": source_descriptor,
        "sourceDescriptorDigest": tagged_jcs_digest(&source_descriptor),
        "decisionEvidence": {
            "kind": "coverage-bound-typed-effects",
            "carrierEdgeId": "surface.builtin.fixture",
            "typedRoutes": [{
                "coverageEdgeId": "surface.native.fixture",
                "actionStages": [{"actionId": "sys:read", "stages": ["requested"]}],
                "internalObserverActionStages": [],
                "sourceBinding": null,
            }],
            "requiredDecisionEdgeIds": if no_effect {
                json!([])
            } else {
                json!(["surface.native.fixture"])
            },
            "selectedNoEffectBranch": if no_effect {
                json!({
                    "carrierEdgeId": "surface.builtin.fixture",
                    "branchId": "metadata",
                    "conditions": [{"fact": "fixture.origin", "equals": "metadata"}],
                    "branchDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                })
            } else {
                Value::Null
            },
        },
        "completion": {
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": TIMEOUT_MILLISECONDS,
        },
    });
    let outer = json!({
        "kind": SOURCE_DESCRIPTOR_KIND,
        "invocation": invocation,
    });
    json!({
        "key": {"surfaceId": "surface.builtin.fixture"},
        "probe": {
            "kind": "loaded-engine-return-record",
            "recordPath": ["[[return]]"],
            "sourceDescriptor": outer,
            "sourceDescriptorDigest": tagged_jcs_digest(&outer),
        },
    })
}

fn validator_fixture_decision() -> Value {
    let root = json!({"kind": "root", "identity": "project-root"});
    json!([{
        "terminalBranchId": "output-shape:fixture",
        "decisionSet": {
            "operationId": "fixture-operation",
            "atomicityGroup": "surface.native.fixture.decision",
            "combination": "conjunction",
            "context": {
                "stage": "requested",
                "actor": root.clone(),
                "constrainedPrincipals": [root.clone()],
            },
            "effects": [{
                "cap": "sys:read",
                "effectOwner": root.clone(),
                "resource": {
                    "kind": "system-info-occurrence",
                    "requested": {"kind": "system-info", "name": "platform"},
                },
            }],
        },
        "gates": [{
            "coverageEdgeId": "surface.native.fixture",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true,
        }],
        "evidence": {
            "operationId": "fixture-operation",
            "stage": "requested",
            "actor": root,
            "outcome": "allow",
        },
    }])
}

#[test]
fn builtin_effects_output_rejects_throw_and_unbound_typed_evidence() {
    assert!(!source_completion_is_exercised(&json!({
        "kind": "throw",
        "rawValueShape": "throw",
        "value": null,
        "errorCode": "ERR_INVALID_ARG_TYPE",
    })));
    let row = validator_fixture_row(false);
    let valid = validator_fixture_decision();
    assert!(validate_source_typed_decisions(&row, "output-shape:fixture", &valid).is_ok());
    assert!(validate_source_typed_decisions(&row, "output-shape:fixture", &json!([])).is_err());

    let mut wrong_branch = valid.clone();
    wrong_branch[0]["terminalBranchId"] = json!("output-shape:other");
    assert!(validate_source_typed_decisions(&row, "output-shape:fixture", &wrong_branch).is_err());

    let mut wrong_edge = valid.clone();
    wrong_edge[0]["decisionSet"]["atomicityGroup"] = json!("surface.native.other.decision");
    wrong_edge[0]["gates"][0]["coverageEdgeId"] = json!("surface.native.other");
    assert!(validate_source_typed_decisions(&row, "output-shape:fixture", &wrong_edge).is_err());

    let mut wrong_action = valid.clone();
    wrong_action[0]["decisionSet"]["effects"][0]["cap"] = json!("fs:read");
    assert!(validate_source_typed_decisions(&row, "output-shape:fixture", &wrong_action).is_err());

    let mut wrong_stage = valid;
    wrong_stage[0]["decisionSet"]["context"]["stage"] = json!("commit");
    wrong_stage[0]["evidence"]["stage"] = json!("commit");
    assert!(validate_source_typed_decisions(&row, "output-shape:fixture", &wrong_stage).is_err());

    let no_effect = validator_fixture_row(true);
    assert!(
        validate_source_typed_decisions(&no_effect, "output-shape:fixture", &json!([]),).is_ok()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_builtin_effects_output_batch() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_BUILTIN_EFFECTS_OUTPUT_PLAN") else {
        eprintln!("IBEX_CAPSEC_BUILTIN_EFFECTS_OUTPUT_PLAN is unset; skipping");
        return;
    };
    let plan_text = std::fs::read_to_string(&plan_path).expect("read builtin effects plan");
    let plan = capsec_semantics::strict_json::parse_strict(&plan_text)
        .expect("builtin effects plan must be strict JSON");
    assert_eq!(plan["planSchema"], PLAN_SCHEMA);
    assert_eq!(
        plan["counts"],
        json!({"registrar": 653, "descriptorResidual": 40})
    );
    let rows = plan["rows"].as_array().expect("builtin effects plan rows");
    assert_eq!(rows.len(), 693);
    for row in rows {
        let _ = invocation(row);
    }
    let _lock = hermes_engine_test_lock().lock().await;
    let execution = execute_rows_with_diagnostics(rows).await;
    let observed = execution.observed;
    let blocked = execution.blocked;
    let controls = execution.controls;
    let fixture_audits = execution.fixture_audits;
    let family_failures = execution.family_failures;
    let cohort_count = |values: &[Value], cohort: &str| {
        values
            .iter()
            .filter(|value| value["cohort"] == cohort)
            .count()
    };
    let control_failures = controls
        .iter()
        .filter(|control| control["validation"]["ok"] != true)
        .count();
    let target_refusals = controls
        .iter()
        .filter(|control| {
            control["validation"]["ok"] == true && control["disposition"] == "target-refused"
        })
        .count();
    let artifact = json!({
        "artifactSchema": ARTIFACT_SCHEMA,
        "planDigest": plan["planDigest"].clone(),
        "catalogKeyDigest": plan["catalogKeyDigest"].clone(),
        "counts": {
            "registrar": {
                "planned": 653,
                "observed": cohort_count(&observed, "registrar"),
                "residual": cohort_count(&blocked, "registrar"),
            },
            "descriptorResidual": {
                "planned": 40,
                "observed": cohort_count(&observed, "descriptor-residual"),
                "residual": cohort_count(&blocked, "descriptor-residual"),
            },
            "positiveControls": {
                "planned": execution.family_count,
                "passed": controls.len() - control_failures - target_refusals,
                "targetRefused": target_refusals,
                "failed": control_failures + family_failures.len(),
            }
        },
        "resolvedFamilyFixtures": fixture_audits,
        "positiveControls": controls,
        "observations": observed,
        "residuals": blocked,
        "familyFailures": family_failures,
    });
    let output_path = std::env::var("IBEX_CAPSEC_BUILTIN_EFFECTS_OUTPUT_RESULT")
        .expect("builtin effects batch requires a fresh result path");
    write_artifact(&output_path, &artifact);

    assert_eq!(artifact["counts"]["registrar"]["observed"], 653);
    assert_eq!(artifact["counts"]["registrar"]["residual"], 0);
    assert_eq!(artifact["counts"]["descriptorResidual"]["observed"], 40);
    assert_eq!(artifact["counts"]["descriptorResidual"]["residual"], 0);
    assert_eq!(artifact["counts"]["positiveControls"]["failed"], 0);
}
