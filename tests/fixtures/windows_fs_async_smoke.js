var fs = require('fs');
var path = require('path');

(async function () {
  var hooks = [
    '__exactFsReadFileAsync', '__exactFsWriteFileAsync', '__exactFsReadAsync',
    '__exactFsWriteAsync', '__exactFsReadvAsync', '__exactFsWritevAsync',
    '__exactFsPathAsync', '__exactFsStatAsync', '__exactFsFsyncSync',
    '__exactFsFdatasyncSync'
  ].map(function (name) { return typeof globalThis[name] === 'function'; });

  // os.tmpdir()/process.env are reduced in the Windows bootstrap. The checked
  // out fixture directory is an absolute, writable Windows path in this test.
  var tempBase = path.dirname(__filename);
  var root = fs.mkdtempSync(path.join(tempBase, 'ibex-winfs-'));
  var original = path.join(root, 'original.txt');
  var renamed = path.join(root, 'renamed.txt');
  var missingCode = null;
  var existsCode = null;
  try {
    await fs.promises.readFile(path.join(root, 'missing.txt'));
  } catch (error) {
    missingCode = error.code;
  }

  await fs.promises.writeFile(original, 'abc');
  var fd = fs.openSync(original, 'a+');
  await fs.promises.rename(original, renamed);
  await fs.promises.write(fd, Buffer.from('Z'), 0, 1, 0);
  var statAfterRename = await fs.promises.fstat(fd);
  fs.fsyncSync(fd);
  fs.fdatasyncSync(fd);
  fs.closeSync(fd);
  try {
    await fs.promises.mkdir(root);
  } catch (error) {
    existsCode = error.code;
  }
  var content = fs.readFileSync(renamed, 'utf8');
  fs.rmSync(root, { recursive: true, force: true });

  console.log('RESULT|' + JSON.stringify({
    hooks: hooks,
    missingCode: missingCode,
    existsCode: existsCode,
    content: content,
    sizeAfterRename: statAfterRename.size
  }));
})().catch(function (error) {
  console.log('ERROR|' + (error && (error.stack || error.message || error)));
  process.exitCode = 1;
});
