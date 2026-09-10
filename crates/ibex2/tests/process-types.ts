import type { Processes, ChildProcess, ProcessStatus, PtyProcess } from '../src/bindings/process';
export async function useProcesses(processes: Processes, signal: AbortSignal): Promise<ProcessStatus> {
  const child: ChildProcess = await processes.spawn({ executable: '/bin/cat', args: [], cwd: '/', env: {} }, signal);
  const read: Promise<Uint8Array | null> = child.stdout.read(1024);
  await child.stdin.write(new Uint8Array([0, 255]));
  await child.stdin.close(); await read;
  const terminal: PtyProcess = await processes.pty({ executable: '/bin/sh', args: [], cwd: '/', env: { TERM: 'xterm' } }, { rows: 24, cols: 80 });
  await terminal.resize({ rows: 40, cols: 100 }); await terminal.close();
  // @ts-expect-error explicit cwd and env are required
  processes.spawn({ executable: '/bin/cat', args: [] });
  // @ts-expect-error no implicit string-to-byte conversion
  child.stdin.write('text');
  // @ts-expect-error PTYs have no stdin half-close
  terminal.input.close();
  return child.wait();
}
