function readText() {
  throw new Error('Exact clipboard not available');
}

function writeText() {
  throw new Error('Exact clipboard not available');
}
module.exports = { readText, writeText };
