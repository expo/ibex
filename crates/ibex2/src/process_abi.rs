//! Installable process bindings: typed spans and private native owners.
//! OS semantics remain entirely in stdlib::process. The JS adapter only owns
//! bounded admissions, byte snapshots, and delivery through the caller's queue.
//! @ref LLP 0068#21-native-processes-and-ptys — shared semantics and trusted host opt-in
use crate::{
    boundary::{HostArg, HostError, HostValue},
    boundary_abi::{clone_grants, leak_value, AbiValue},
    grant::GrantSet,
    stdlib::{
        abort::AbortController,
        process::{Command, ExitStatus, Input, Output, Process, Processes, Pty, PtySize},
    },
    task::RuntimeState,
};
use std::{
    ffi::c_void,
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
};

const MAX_CHILDREN: usize = 16;
const MAX_TASKS: usize = 128;
const MAX_BYTES: usize = 65536;
#[derive(Default)]
struct Table {
    enabled: bool,
    closed: bool,
    children: Vec<Weak<Entry>>,
}
#[derive(Default)]
pub(crate) struct Registry {
    table: Mutex<Table>,
    tasks: AtomicUsize,
}
impl Registry {
    pub(crate) fn enable(&self) -> Result<(), HostError> {
        let mut table = self.table.lock().unwrap();
        if table.closed {
            return Err(invalid("process context is closed"));
        }
        table.enabled = true;
        Ok(())
    }
    pub(crate) fn shutdown(&self) {
        let entries = {
            let mut table = self.table.lock().unwrap();
            table.closed = true;
            std::mem::take(&mut table.children)
        };
        for entry in entries.into_iter().filter_map(|e| e.upgrade()) {
            entry.dispose();
        }
    }
    fn prepare(&self, grants: Arc<GrantSet>, args: &[HostArg]) -> Result<Arc<Entry>, HostError> {
        let (command, size) = parse_command(args)?;
        let mut table = self.table.lock().unwrap();
        if table.closed {
            return Err(invalid("process context is closed"));
        }
        let api = Processes::new(grants, table.enabled);
        let control = AbortController::new();
        api.check(&command, size.is_some(), &control.signal())?;
        table.children.retain(|e| {
            e.upgrade()
                .is_some_and(|e| !e.closed.load(Ordering::Acquire))
        });
        if table.children.len() >= MAX_CHILDREN {
            return Err(invalid(
                "process limit: close a child before opening another",
            ));
        }
        let entry = Arc::new(Entry {
            api,
            command: Mutex::new(Some(command)),
            size,
            control,
            child: Mutex::new(None),
            input: Mutex::new(None),
            output: [Mutex::new(None), Mutex::new(None)],
            busy: std::array::from_fn(|_| AtomicBool::new(false)),
            disposing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        table.children.push(Arc::downgrade(&entry));
        Ok(entry)
    }
}
enum Native {
    Pipe(Process),
    Terminal(Pty),
}
impl Native {
    fn id(&self) -> u32 {
        match self {
            Self::Pipe(c) => c.id(),
            Self::Terminal(c) => c.id(),
        }
    }
    fn wait(&self) -> Result<ExitStatus, HostError> {
        match self {
            Self::Pipe(c) => c.wait(),
            Self::Terminal(c) => c.wait(),
        }
    }
}
struct Entry {
    api: Processes,
    command: Mutex<Option<Command>>,
    size: Option<PtySize>,
    control: AbortController,
    child: Mutex<Option<Arc<Native>>>,
    input: Mutex<Option<Input>>,
    output: [Mutex<Option<Output>>; 2],
    busy: [AtomicBool; 7],
    disposing: AtomicBool,
    closed: AtomicBool,
}
impl Entry {
    fn native(&self) -> Result<Arc<Native>, HostError> {
        self.child
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| invalid("process is not launched"))
    }
    fn cancel(&self) -> Result<HostValue, HostError> {
        self.control.abort();
        self.command.lock().unwrap().take();
        let child = self.child.lock().unwrap().clone();
        let result = match child {
            Some(child) => child.wait().map(status),
            None => Ok(HostValue::Undefined),
        };
        self.closed.store(true, Ordering::Release);
        result
    }
    fn dispose(self: &Arc<Self>) {
        if self.closed.load(Ordering::Acquire) || self.disposing.swap(true, Ordering::AcqRel) {
            return;
        }
        let entry = self.clone();
        // At most one cleanup per live child, at most MAX_CHILDREN children.
        // Cleanup cannot queue behind blocked filesystem or process I/O.
        if std::thread::Builder::new()
            .name("ibex-process-close".into())
            .spawn(move || {
                let _ = entry.cancel();
            })
            .is_err()
        {
            // Resource exhaustion must not strand an owned child.
            let _ = self.cancel();
        }
    }
    fn run(&self, op: u32, args: &[HostValue]) -> Result<HostValue, HostError> {
        match op {
            0 => {
                let command = self
                    .command
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| invalid("process already launched"))?;
                let child = if let Some(size) = self.size {
                    let mut c = self.api.pty(command, size, &self.control.signal())?;
                    *self.input.lock().unwrap() = c.input.take();
                    *self.output[0].lock().unwrap() = c.output.take();
                    Native::Terminal(c)
                } else {
                    let mut c = self.api.spawn(command, &self.control.signal())?;
                    *self.input.lock().unwrap() = c.stdin.take();
                    *self.output[0].lock().unwrap() = c.stdout.take();
                    *self.output[1].lock().unwrap() = c.stderr.take();
                    Native::Pipe(c)
                };
                let pid = child.id();
                *self.child.lock().unwrap() = Some(Arc::new(child));
                self.control.signal().check()?;
                Ok(HostValue::Number(pid as f64))
            }
            1 | 2 => {
                let n = match args.first() {
                    Some(HostValue::Number(n)) => *n as usize,
                    _ => unreachable!(),
                };
                let mut bytes = vec![0; n];
                let n = self.output[(op - 1) as usize]
                    .lock()
                    .unwrap()
                    .as_mut()
                    .ok_or_else(|| invalid("process output is closed or unavailable"))?
                    .read(&mut bytes)
                    .map_err(io_error)?;
                bytes.truncate(n);
                Ok(if n == 0 {
                    HostValue::Null
                } else {
                    HostValue::Bytes(bytes)
                })
            }
            3 => {
                let Some(HostValue::Bytes(bytes)) = args.first() else {
                    unreachable!()
                };
                self.input
                    .lock()
                    .unwrap()
                    .as_mut()
                    .ok_or_else(|| invalid("process input is closed"))?
                    .write_all(bytes)
                    .map_err(io_error)?;
                Ok(HostValue::Undefined)
            }
            4 => {
                self.input.lock().unwrap().take();
                Ok(HostValue::Undefined)
            }
            5 => self.native()?.wait().map(status),
            6 => self.cancel(),
            7 => {
                let (HostValue::Number(rows), HostValue::Number(cols)) = (&args[0], &args[1])
                else {
                    unreachable!()
                };
                match self.native()?.as_ref() {
                    Native::Terminal(c) => c.resize(PtySize {
                        rows: *rows as u16,
                        cols: *cols as u16,
                    })?,
                    _ => return Err(invalid("process has no terminal")),
                }
                Ok(HostValue::Undefined)
            }
            _ => Err(invalid("unknown process operation")),
        }
    }
}

#[cfg(test)]
#[path = "process_abi_tests.rs"]
mod tests;
fn status(s: ExitStatus) -> HostValue {
    HostValue::Number(s.code.unwrap_or_else(|| -s.signal.unwrap_or(0)) as f64)
}
fn invalid(s: &str) -> HostError {
    HostError::InvalidArgument(s.into())
}
fn io_error(e: std::io::Error) -> HostError {
    HostError::Failed(format!("process: {e}"))
}
fn integer(n: f64, max: usize) -> Result<usize, HostError> {
    if n.is_finite() && n.fract() == 0.0 && n >= 0.0 && n <= max as f64 {
        Ok(n as usize)
    } else {
        Err(invalid("invalid process integer"))
    }
}
fn number(args: &[HostArg], i: usize, max: usize) -> Result<usize, HostError> {
    match args.get(i) {
        Some(HostArg::Number(n)) => integer(*n, max),
        _ => Err(invalid("process integer expected")),
    }
}
fn string<'a>(args: &[HostArg<'a>], i: usize) -> Result<&'a str, HostError> {
    match args.get(i) {
        Some(HostArg::Str(s)) => Ok(s),
        _ => Err(invalid("process string expected")),
    }
}
fn parse_command(args: &[HostArg]) -> Result<(Command, Option<PtySize>), HostError> {
    let terminal = number(args, 0, 1)? == 1;
    let size = if terminal {
        let size = PtySize {
            rows: number(args, 1, 65535)? as u16,
            cols: number(args, 2, 65535)? as u16,
        };
        size.validate()?;
        Some(size)
    } else {
        if number(args, 1, 0)? != 0 || number(args, 2, 0)? != 0 {
            return Err(invalid("pipe dimensions"));
        }
        None
    };
    let executable = string(args, 3)?.to_owned();
    let cwd = string(args, 4)?.to_owned();
    let argc = number(args, 5, 256)?;
    let mut argv = Vec::with_capacity(argc);
    for i in 0..argc {
        argv.push(string(args, 6 + i)?.to_owned());
    }
    let envc = number(args, 6 + argc, 256)?;
    let offset = 7 + argc;
    if args.len() != offset + envc * 2 {
        return Err(invalid("unexpected process launch arguments"));
    }
    let mut env = std::collections::BTreeMap::new();
    for i in 0..envc {
        if env
            .insert(
                string(args, offset + i * 2)?.to_owned(),
                string(args, offset + i * 2 + 1)?.to_owned(),
            )
            .is_some()
        {
            return Err(invalid("duplicate environment variable"));
        }
    }
    Ok((
        Command {
            executable,
            args: argv,
            cwd,
            env,
        },
        size,
    ))
}
// The trusted adapter supplies live native pointers. No pointer or resource ID
// is exposed in the installed JS API. Strict lengths precede every snapshot.
unsafe fn borrow_args<'a>(
    ptr: *const AbiValue,
    n: usize,
    max: usize,
) -> Result<Vec<HostArg<'a>>, HostError> {
    if n > max || (n > 0 && ptr.is_null()) {
        return Err(invalid("invalid process argument span"));
    }
    let raw = if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, n)
    };
    let mut total = 0usize;
    for value in raw {
        if value.len > 0 && value.data.is_null() {
            return Err(invalid("null process byte span"));
        }
        total = total
            .checked_add(value.len)
            .ok_or_else(|| invalid("process input too large"))?;
    }
    if total > 1024 * 1024 {
        return Err(invalid("process launch input exceeds 1 MiB"));
    }
    raw.iter().map(|value| value.borrow()).collect()
}
struct Owner {
    registry: Arc<Registry>,
    entry: Arc<Entry>,
}
// Shared by the worker and the adapter's pending promise. Worker completion
// alone cannot release a lane/budget: the adapter retains its Arc through
// delivery (or detach), bounding completed but undelivered byte payloads too.
struct Ticket {
    state: Arc<RuntimeState>,
    entry: Arc<Entry>,
    lane: usize,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        self.entry.busy[self.lane].store(false, Ordering::Release);
        self.state.processes.tasks.fetch_sub(1, Ordering::AcqRel);
    }
}
/// # Safety
/// queue/grants are live Ibex pointers; argv spans argc values; out is writable.
#[no_mangle]
pub unsafe extern "C" fn ibex2_process_prepare(
    queue: *const RuntimeState,
    grants: *const GrantSet,
    argv: *const AbiValue,
    argc: usize,
    out: *mut AbiValue,
) -> *mut c_void {
    if out.is_null() {
        return std::ptr::null_mut();
    }
    let result = (|| {
        let state =
            crate::task::clone_queue(queue).ok_or_else(|| invalid("missing process context"))?;
        let grants = clone_grants(grants).unwrap_or_else(|| Arc::new(GrantSet::none()));
        let args = borrow_args(argv, argc, 775)?;
        let entry = state.processes.prepare(grants, &args)?;
        Ok::<_, HostError>(Owner {
            registry: state.processes.clone(),
            entry,
        })
    })();
    match result {
        Ok(owner) => {
            *out = leak_value(HostValue::Undefined);
            Box::into_raw(Box::new(owner)).cast()
        }
        Err(e) => {
            *out = leak_value(HostValue::Str(e.to_string()));
            std::ptr::null_mut()
        }
    }
}
/// # Safety
/// owner is null or an unreleased pointer from process_prepare.
#[no_mangle]
pub unsafe extern "C" fn ibex2_process_owner_destroy(owner: *mut c_void) {
    if !owner.is_null() {
        let owner = Box::from_raw(owner.cast::<Owner>());
        owner.entry.dispose();
    }
}
/// # Safety
/// ticket is null or an unreleased pointer from process_begin.
/// Retain it until its completion is consumed/discarded or the context closes.
#[no_mangle]
pub unsafe extern "C" fn ibex2_process_ticket_destroy(ticket: *mut c_void) {
    if !ticket.is_null() {
        drop(Box::from_raw(ticket.cast::<Arc<Ticket>>()));
    }
}
/// # Safety
/// queue/owner are live native pointers; argv spans argc values; out is writable.
/// A successful call returns a ticket retained until JS delivery or detach.
#[no_mangle]
pub unsafe extern "C" fn ibex2_process_begin(
    queue: *const RuntimeState,
    owner: *const c_void,
    op: u32,
    argv: *const AbiValue,
    argc: usize,
    id: u64,
    out: *mut AbiValue,
) -> *mut c_void {
    if out.is_null() {
        return std::ptr::null_mut();
    }
    let result = (|| {
        let state =
            crate::task::clone_queue(queue).ok_or_else(|| invalid("missing process context"))?;
        let owner = owner
            .cast::<Owner>()
            .as_ref()
            .ok_or_else(|| invalid("missing process owner"))?;
        if !Arc::ptr_eq(&state.processes, &owner.registry)
            || owner.registry.table.lock().unwrap().closed
        {
            return Err(invalid("process context is closed or different"));
        }
        let args = borrow_args(argv, argc, 2)?;
        let owned = match op {
            0 | 4 | 5 | 6 if args.is_empty() => vec![],
            1 | 2 if args.len() == 1 => {
                let n = number(&args, 0, MAX_BYTES)?;
                if n == 0 {
                    return Err(invalid("process read size must be nonzero"));
                }
                vec![HostValue::Number(n as f64)]
            }
            3 if args.len() == 1 => {
                let Some(HostArg::Bytes(bytes)) = args.first() else {
                    return Err(invalid("process write requires bytes"));
                };
                if bytes.len() > MAX_BYTES {
                    return Err(invalid("process write exceeds 64 KiB"));
                }
                vec![HostValue::Bytes(bytes.to_vec())]
            }
            7 if args.len() == 2 => {
                let rows = number(&args, 0, 65535)?;
                let cols = number(&args, 1, 65535)?;
                PtySize {
                    rows: rows as u16,
                    cols: cols as u16,
                }
                .validate()?;
                vec![
                    HostValue::Number(rows as f64),
                    HostValue::Number(cols as f64),
                ]
            }
            _ => return Err(invalid("invalid process operation arguments")),
        };
        let lane = match op {
            0..=3 => op as usize,
            4 => 3,
            5 => 4,
            6 => 5,
            7 => 6,
            _ => unreachable!(),
        };
        if owner.entry.busy[lane].swap(true, Ordering::AcqRel) {
            return Err(invalid("process operation already pending"));
        }
        if state.processes.tasks.fetch_add(1, Ordering::AcqRel) >= MAX_TASKS {
            state.processes.tasks.fetch_sub(1, Ordering::AcqRel);
            owner.entry.busy[lane].store(false, Ordering::Release);
            return Err(invalid("process completion limit"));
        }
        let ticket = Arc::new(Ticket {
            state: state.clone(),
            entry: owner.entry.clone(),
            lane,
        });
        let worker = ticket.clone();
        state.task_started();
        let launched = std::thread::Builder::new()
            .name("ibex-process".into())
            .spawn(move || {
                let result = worker.entry.run(op, &owned);
                let state = worker.state.clone();
                drop(worker);
                state.queue.complete(id, result);
                state.task_finished();
            });
        if let Err(error) = launched {
            state.task_finished();
            return Err(io_error(error));
        }
        Ok::<_, HostError>(ticket)
    })();
    match result {
        Ok(ticket) => {
            *out = leak_value(HostValue::Undefined);
            Box::into_raw(Box::new(ticket)).cast()
        }
        Err(e) => {
            *out = leak_value(HostValue::Str(e.to_string()));
            std::ptr::null_mut()
        }
    }
}
