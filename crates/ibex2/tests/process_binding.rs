//! Real borrowed Hermes, explicit installation and caller-owned checkpoints.
#![cfg(all(feature = "hermes", any(target_os = "macos", target_os = "linux")))]
use ibex2::{bindings::Context, grant::GrantSet};
use std::{
    ffi::{c_char, c_void, CStr},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
extern "C" {
    fn process_consumer_create(
        queue: *const c_void,
        grants: *const c_void,
        factory: *const u8,
        len: usize,
        harden: *const u8,
        harden_len: usize,
        error: *mut *mut c_char,
    ) -> *mut c_void;
    fn storage_consumer_eval(
        h: *mut c_void,
        data: *const u8,
        len: usize,
        out: *mut *mut c_char,
    ) -> i32;
    fn storage_consumer_step(h: *mut c_void, deliver: bool, out: *mut *mut c_char) -> i32;
    fn storage_consumer_detach(h: *mut c_void);
    fn storage_consumer_destroy(h: *mut c_void);
    fn storage_consumer_free(s: *mut c_char);
}
fn take(s: *mut c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    let result = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    unsafe { storage_consumer_free(s) };
    result
}
struct Consumer {
    handle: *mut c_void,
    context: Context,
    directory: PathBuf,
}
impl Consumer {
    fn new(grants: &str, enabled: bool, hardened: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ibex-process-js-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let context = Context::new(GrantSet::parse(grants).unwrap());
        if enabled {
            context.enable_process_support().unwrap();
        }
        let factory = Self::compile(&directory, include_str!("../src/bindings/process.js"));
        let harden = include_bytes!(concat!(env!("OUT_DIR"), "/harden.hbc"));
        let mut error = std::ptr::null_mut();
        let handle = unsafe {
            process_consumer_create(
                context.state_ptr(),
                context.grants_ptr(),
                factory.as_ptr(),
                factory.len(),
                harden.as_ptr(),
                if hardened { harden.len() } else { 0 },
                &mut error,
            )
        };
        assert!(!handle.is_null(), "{}", take(error));
        Self {
            handle,
            context,
            directory,
        }
    }
    fn compile(directory: &std::path::Path, source: &str) -> Vec<u8> {
        let input = directory.join("test.js");
        let output = directory.join("test.hbc");
        std::fs::write(&input, source).unwrap();
        let result = std::process::Command::new(
            std::env::var("IBEX2_HERMESC").expect("test needs matching hermesc"),
        )
        .args(["-O", "-emit-binary", "-out"])
        .arg(&output)
        .arg(&input)
        .output()
        .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::read(output).unwrap()
    }
    fn eval(&self, source: &str) -> Result<String, String> {
        let bytes = Self::compile(&self.directory, source);
        let mut out = std::ptr::null_mut();
        let status =
            unsafe { storage_consumer_eval(self.handle, bytes.as_ptr(), bytes.len(), &mut out) };
        let text = take(out);
        if status == 0 {
            Ok(text)
        } else {
            Err(text)
        }
    }
    fn step(&self, deliver: bool) -> i32 {
        let mut out = std::ptr::null_mut();
        let n = unsafe { storage_consumer_step(self.handle, deliver, &mut out) };
        assert!(n >= 0, "{}", take(out));
        n
    }
    fn finish(&self) -> String {
        let end = Instant::now() + Duration::from_secs(8);
        loop {
            self.step(false);
            let result = self.eval("globalThis.result || ''").unwrap();
            if !result.is_empty() {
                return result;
            }
            assert!(Instant::now() < end, "process promise did not settle");
            self.context.wait(Duration::from_millis(10));
            self.step(true);
        }
    }
    fn run(&self, body: &str) -> String {
        self.eval(&format!("globalThis.result=''; (async function(){{ {body} }})().then(()=>result='ok', e=>result=String(e));")).unwrap();
        self.finish()
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        unsafe { storage_consumer_destroy(self.handle) };
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn host_enablement_grants_and_hardening_are_independent_gates() {
    for (grant, enabled) in [
        ("process.spawn /bin/sh", false),
        ("", true),
        ("process.pty /bin/sh", true),
    ] {
        let c = Consumer::new(grant, enabled, true);
        let marker = c.directory.join("forbidden");
        let source = format!("let refused=false; try {{ await processes.spawn({{executable:'/bin/sh',args:['-c','printf bad > \"$MARKER\"'],cwd:'/',env:{{MARKER:{}}}}}); }} catch(e) {{refused=String(e).includes('denied');}} if(!refused) throw Error('authority');", serde_json::to_string(&marker).unwrap());
        assert_eq!(c.run(&source), "ok");
        assert!(!marker.exists());
    }
    let c = Consumer::new("process.spawn /bin/sh", true, false);
    assert!(c
        .run("await processes.spawn({executable:'/bin/sh',args:[],cwd:'/',env:{}});")
        .contains("harden"));
}

#[test]
fn byte_pipes_literal_arguments_environment_and_checkpoints() {
    let c = Consumer::new(
        "process.spawn /bin/cat\nprocess.spawn /bin/sh\nprocess.spawn /usr/bin/env",
        true,
        true,
    );
    c.eval("globalThis.result=''; processes.spawn({executable:'/bin/cat',args:[],cwd:'/',env:{}}).then(c=>{globalThis.child=c;result='opened';});").unwrap();
    assert!(c.context.wait(Duration::from_secs(5)));
    assert_eq!(c.eval("result").unwrap(), "");
    assert_eq!(c.step(true), 1);
    assert_eq!(c.eval("result").unwrap(), "");
    c.step(false);
    assert_eq!(c.eval("result").unwrap(), "opened");
    assert_eq!(c.run(r#"
      if(!Object.isFrozen(processes)||!Object.isFrozen(child)) throw Error('freeze');
      const data=new Uint8Array([99,0,255,3,4,13,10,88]).subarray(1,7);
      const read=child.stdout.read(6);
      await child.stdin.write(data); await child.stdin.close();
      const out=await read;
      if(!(out instanceof Uint8Array)||out.join(',')!==data.join(',')) throw Error('bytes');
      if(await child.stdout.read()!==null) throw Error('EOF');
      const status=await child.wait(); if(status.code!==0||status.signal!==null||!status.success) throw Error('status');
      const env=await processes.spawn({executable:'/usr/bin/env',args:[],cwd:'/',env:{ONLY:'literal'}});
      const b=await env.stdout.read(); if(String.fromCharCode.apply(null,b)!=='ONLY=literal\n') throw Error('ambient env');
      await env.wait();
      const sh=await processes.spawn({executable:'/bin/sh',args:['-c','printf "%s" "$1"; printf "%s" "$PWD" >&2; exit 23','fixture','$(nope); *'],cwd:'/',env:{}});
      if(String.fromCharCode.apply(null,await sh.stdout.read())!=='$(nope); *') throw Error('argv');
      if(String.fromCharCode.apply(null,await sh.stderr.read())!=='/') throw Error('cwd');
      if((await sh.wait()).code!==23) throw Error('exit');
    "#), "ok");
}

#[test]
fn pty_raw_bytes_resize_and_close() {
    let c = Consumer::new("process.pty /bin/cat\nprocess.pty /bin/sh", true, true);
    assert_eq!(c.run(r#"
      const tty=await processes.pty({executable:'/bin/sh',args:['-c','exec 3</dev/tty; printf ready; read answer; /bin/stty size'],cwd:'/',env:{}},{rows:24,cols:80});
      if(String.fromCharCode.apply(null,await tty.output.read())!=='ready') throw Error('ctty');
      await tty.resize({rows:43,cols:121}); await tty.input.write(new Uint8Array([10]));
      if(String.fromCharCode.apply(null,await tty.output.read())!=='43 121\n') throw Error('resize');
      await tty.wait();
      const cat=await processes.pty({executable:'/bin/cat',args:[],cwd:'/',env:{}},{rows:24,cols:80});
      const bytes=new Uint8Array([0,3,4,255,13,10]); const read=cat.output.read();
      await cat.input.write(bytes); if((await read).join(',')!==bytes.join(',')) throw Error('raw');
      if((await cat.close()).signal!==9) throw Error('close');
      try { await cat.output.read(); throw Error('read after close'); } catch(e) { if(e.message==='read after close') throw e; }
    "#),"ok");
}

#[test]
fn cancellation_and_stream_admission_are_bounded() {
    let c = Consumer::new(
        "process.spawn /bin/sleep\nprocess.spawn /bin/sh",
        true,
        true,
    );
    assert_eq!(c.run(r#"
      const c=await processes.spawn({executable:'/bin/sleep',args:['30'],cwd:'/',env:{}});
      const read=c.stdout.read().then(()=>false,()=>true); const wait=c.wait();
      let refused=false; try { await c.stdout.read(); } catch(e) {refused=true;} if(!refused) throw Error('queued read');
      refused=false; try { await c.stdin.write(new Uint8Array(65537)); } catch(e) {refused=true;} if(!refused) throw Error('large write');
      const write=c.stdin.write(new Uint8Array(65536)).catch(()=>{});
      await c.cancel(); if(!(await read)||(await wait).signal!==9) throw Error('abort'); await write;
      const signal={aborted:true,reason:'pre-aborted',addEventListener(){},removeEventListener(){}};
      try {await processes.spawn({executable:'/bin/sh',args:['-c','exit 0'],cwd:'/',env:{}},signal);throw Error('preabort');}
      catch(e){if(e!=='pre-aborted')throw e;}
      let fire;const live={aborted:false,reason:'stop',addEventListener(t,f){fire=f;},removeEventListener(){}};
      const opening=processes.spawn({executable:'/bin/sleep',args:['30'],cwd:'/',env:{}},live);
      live.aborted=true;fire();
      try {await opening;throw Error('launch abort');}catch(e){if(e!=='stop')throw e;}
    "#),"ok");
}

#[test]
fn throwing_signal_removal_cannot_prevent_cancellation_and_reaping() {
    for abort_event in [false, true] {
        let c = Consumer::new("process.spawn /bin/sleep", true, true);
        assert_eq!(c.run(r#"
          globalThis.fire=null; globalThis.removals=0;
          globalThis.signal={aborted:false,reason:'stop',
            addEventListener(t,f){fire=f;},
            removeEventListener(){removals++; if(removals===1)fire(); throw Error('remove failed');}};
          globalThis.child=await processes.spawn({executable:'/bin/sleep',args:['30'],cwd:'/',env:{}},signal);
        "#), "ok");
        let pid: i32 = c.eval("child.pid").unwrap().parse().unwrap();
        let cancel = if abort_event {
            "signal.aborted=true; fire(); const status=await child.wait(); if(status.signal!==9)throw Error('abort failed');"
        } else {
            "const status=await child.cancel(); if(status.signal!==9)throw Error('cancel failed');"
        };
        assert_eq!(c.run(cancel), "ok");
        assert_eq!(c.eval("String(removals)").unwrap(), "1");
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

#[test]
fn throwing_signal_setup_releases_prepared_slots_despite_retained_callbacks() {
    let c = Consumer::new(
        "process.spawn /bin/sleep\nprocess.pty /bin/sleep",
        true,
        true,
    );
    assert_eq!(c.run(r#"
      globalThis.retained=[];
      const command={executable:'/bin/sleep',args:['30'],cwd:'/',env:{}};
      for(let terminal=0;terminal<2;terminal++) {
        const failure=Error('add failed');
        const signal={aborted:false,reason:'stop',
          addEventListener(t,f){retained.push(f); throw failure;},
          removeEventListener(){throw Error('remove failed too');}};
        for(let i=0;i<16;i++) {
          let rejected=false;
          try {
            await (terminal ? processes.pty(command,{rows:24,cols:80},signal) : processes.spawn(command,signal));
          } catch(e) {if(e!==failure)throw e; rejected=true;}
          if(!rejected)throw Error('setup succeeded');
        }
        // Failed openers still have reachable listener closures. Slot release
        // must finish before rejection; GC cannot rescue this test.
        const child=await (terminal ? processes.pty(command,{rows:24,cols:80}) : processes.spawn(command));
        if((await child.close()).signal!==9)throw Error('replacement failed');
      }
      if(retained.length!==32)throw Error('listeners not retained');
      for(const callback of retained)callback();
    "#), "ok");
}

#[test]
fn unread_js_output_backpressures_the_native_child() {
    let c = Consumer::new("process.spawn /bin/sh", true, true);
    let marker = c.directory.join("finished");
    let command=format!("globalThis.child=await processes.spawn({{executable:'/bin/sh',args:['-c','/bin/dd if=/dev/zero bs=65536 count=128 2>/dev/null; printf done > \"$MARKER\"'],cwd:'/',env:{{MARKER:{}}}}});",serde_json::to_string(&marker).unwrap());
    assert_eq!(c.run(&command), "ok");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!marker.exists(), "adapter drained output without a JS read");
    assert_eq!(c.run("const exit=child.wait(); let total=0; for (;;) {const bytes=await child.stdout.read();if(bytes===null)break;total+=bytes.length;} if(total!==8388608||(await exit).code!==0)throw Error('stream'); await child.close();"),"ok");
    assert_eq!(std::fs::read(marker).unwrap(), b"done");
}

#[test]
fn detach_cancels_a_child_with_a_pending_read_and_refuses_retained_capabilities() {
    let c = Consumer::new("process.spawn /bin/sleep", true, true);
    assert_eq!(c.run("globalThis.child=await processes.spawn({executable:'/bin/sleep',args:['30'],cwd:'/',env:{}}); child.stdout.read().catch(()=>{});"),"ok");
    let pid: i32 = c.eval("child.pid").unwrap().parse().unwrap();
    unsafe { storage_consumer_detach(c.handle) };
    assert!(c
        .run("await processes.spawn({executable:'/bin/sleep',args:['30'],cwd:'/',env:{}});")
        .contains("detached"));
    let end = Instant::now() + Duration::from_secs(5);
    while unsafe { libc::kill(pid, 0) } == 0 {
        assert!(Instant::now() < end, "detach left child alive");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
