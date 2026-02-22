function isatty(fd) {
  var p = typeof globalThis !== 'undefined' && globalThis.process;
  if (!p) return false;
  if (fd === 0) return !!p.stdin && !!p.stdin.isTTY;
  if (fd === 1) return !!p.stdout && !!p.stdout.isTTY;
  if (fd === 2) return !!p.stderr && !!p.stderr.isTTY;
  return false;
}

function ReadStream() {
  throw new Error("tty.ReadStream is not supported");
}

function WriteStream() {
  throw new Error("tty.WriteStream is not supported");
}

module.exports = {
  isatty: isatty,
  ReadStream: ReadStream,
  WriteStream: WriteStream
};
