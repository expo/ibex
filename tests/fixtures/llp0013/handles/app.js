var path = require('path');
var lib = require('image-lib');
var imagesDir = process.env.IMAGES;
var secretPath = process.env.SECRET;
// The app holds fs; it mints a read handle scoped to the images dir and hands it
// to image-lib along with a revoke demo.
var handle = Ibex.fs.readHandle(imagesDir);
console.log('result: ' + lib.run(handle, imagesDir, secretPath));
// Revocation cascade: after revoke, the handle (and its scoped children) die.
handle.revoke();
try { handle.readTextSync(imagesDir + '/logo.png'); console.log('after-revoke: LEAKED'); }
catch (e) { console.log('after-revoke: DENIED'); }
