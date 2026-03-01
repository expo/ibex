// node:console module — re-exports the global console with Console constructor
module.exports = console;
// Use the enhanced Console from console-enhance.js bootstrap
// (which supports custom streams, group indentation, etc.)
if (console.Console) {
  module.exports.Console = console.Console;
}
