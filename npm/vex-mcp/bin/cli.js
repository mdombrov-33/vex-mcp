#!/usr/bin/env node
"use strict";

// Thin launcher for the prebuilt vex-mcp binary.
//
// `vex-mcp` ships no binary itself. The matching platform package
// (e.g. vex-mcp-darwin-arm64) is pulled in as an optional dependency and
// installed only on the host it targets, via its `os`/`cpu` fields. This
// shim finds that package's binary and execs it, passing stdio straight
// through — the JSON-RPC channel on stdin/stdout must stay untouched.

const path = require("path");
const { spawnSync } = require("child_process");

const PLATFORM_PACKAGES = {
  "darwin arm64": "@vexenbay/vex-mcp-darwin-arm64",
  "darwin x64": "@vexenbay/vex-mcp-darwin-x64",
  "linux arm64": "@vexenbay/vex-mcp-linux-arm64",
  "linux x64": "@vexenbay/vex-mcp-linux-x64",
  "win32 x64": "@vexenbay/vex-mcp-win32-x64",
};

const key = `${process.platform} ${process.arch}`;
const pkg = PLATFORM_PACKAGES[key];

if (!pkg) {
  console.error(
    `vex-mcp: no prebuilt binary for ${key}.\n` +
      `Supported platforms: ${Object.keys(PLATFORM_PACKAGES).join(", ")}.\n` +
      `Build from source instead: cargo install vex-mcp`,
  );
  process.exit(1);
}

const binName = process.platform === "win32" ? "vex-mcp.exe" : "vex-mcp";

let binPath;
try {
  // Resolve via package.json — require.resolve can't resolve a binary file
  // directly (it would append .js/.node), but the manifest always resolves.
  const manifest = require.resolve(`${pkg}/package.json`);
  binPath = path.join(path.dirname(manifest), binName);
} catch {
  console.error(
    `vex-mcp: the platform package "${pkg}" is not installed.\n` +
      `This usually means optional dependencies were skipped during install.\n` +
      `Reinstall without --no-optional, or build from source: cargo install vex-mcp`,
  );
  process.exit(1);
}

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`vex-mcp: failed to launch binary: ${result.error.message}`);
  process.exit(1);
}

// Mirror the binary's exit. spawnSync reports a signal kill via `signal`
// with a null status; surface that as the conventional 128 + signal code.
if (result.status === null && result.signal) {
  process.exit(1);
}
process.exit(result.status);
