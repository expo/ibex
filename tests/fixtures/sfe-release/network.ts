async function main() {
  const url = process.argv[2];
  if (!url) {
    throw new Error("network fixture requires a URL argument");
  }

  const response = await fetch(url);
  const body = await response.text();
  console.log(`fetch=${response.status}:${body.trim()}`);
  process.exitCode = response.ok && body.trim() === "sfe-network-ok" ? 0 : 9;
}

void main();
