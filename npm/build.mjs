// Assemble the npm packages for publishing.
//
// Usage: node npm/build.mjs <version> <dist-dir>
//   <version>   release version, e.g. 0.1.2 (no leading "v")
//   <dist-dir>  directory holding the GitHub Release archives
//               (vex-mcp-<triple>.tar.gz and the windows .zip)
//
// It writes one ready-to-publish platform package per target under
// npm/platforms/<pkg>/, and rewrites the main package's version +
// optionalDependencies to match. The CI job then `npm publish`es each
// platform package, followed by npm/vex-mcp.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

const version = process.argv[2];
const distDir = process.argv[3];

if (!version || !distDir) {
  console.error("usage: node npm/build.mjs <version> <dist-dir>");
  process.exit(1);
}

// Rust target triple -> npm platform package metadata.
const TARGETS = [
  { triple: "aarch64-apple-darwin", pkg: "@vexenbay/vex-mcp-darwin-arm64", os: "darwin", cpu: "arm64", windows: false },
  { triple: "x86_64-apple-darwin", pkg: "@vexenbay/vex-mcp-darwin-x64", os: "darwin", cpu: "x64", windows: false },
  { triple: "aarch64-unknown-linux-musl", pkg: "@vexenbay/vex-mcp-linux-arm64", os: "linux", cpu: "arm64", windows: false },
  { triple: "x86_64-unknown-linux-musl", pkg: "@vexenbay/vex-mcp-linux-x64", os: "linux", cpu: "x64", windows: false },
  { triple: "x86_64-pc-windows-msvc", pkg: "@vexenbay/vex-mcp-win32-x64", os: "win32", cpu: "x64", windows: true },
];

const platformsDir = join(__dirname, "platforms");
rmSync(platformsDir, { recursive: true, force: true });

for (const t of TARGETS) {
  const binName = t.windows ? "vex-mcp.exe" : "vex-mcp";
  // Flat output dir (scope stripped) so the CI publish glob stays simple;
  // npm publishes by the manifest `name`, not the directory name.
  const outDir = join(platformsDir, t.pkg.replace(/^@[^/]+\//, ""));
  mkdirSync(outDir, { recursive: true });

  // Extract the binary out of the release archive into the package dir.
  if (t.windows) {
    const archive = join(distDir, `vex-mcp-${t.triple}.zip`);
    assertExists(archive);
    execFileSync("unzip", ["-o", "-j", archive, binName, "-d", outDir], { stdio: "inherit" });
  } else {
    const archive = join(distDir, `vex-mcp-${t.triple}.tar.gz`);
    assertExists(archive);
    execFileSync("tar", ["-xzf", archive, "-C", outDir, binName], { stdio: "inherit" });
  }
  assertExists(join(outDir, binName));

  const pkgJson = {
    name: t.pkg,
    version,
    description: `Prebuilt vex-mcp binary for ${t.os}-${t.cpu}.`,
    license: "MIT",
    homepage: "https://github.com/mdombrov-33/vex-mcp#readme",
    repository: { type: "git", url: "git+https://github.com/mdombrov-33/vex-mcp.git" },
    os: [t.os],
    cpu: [t.cpu],
    files: [binName],
  };
  writeFileSync(join(outDir, "package.json"), JSON.stringify(pkgJson, null, 2) + "\n");
  console.log(`assembled ${t.pkg}@${version}`);
}

// Rewrite the main package's version and pin every optional dep to it.
const mainPath = join(__dirname, "vex-mcp", "package.json");
const main = JSON.parse(readFileSync(mainPath, "utf8"));
main.version = version;
for (const t of TARGETS) {
  main.optionalDependencies[t.pkg] = version;
}
writeFileSync(mainPath, JSON.stringify(main, null, 2) + "\n");
console.log(`patched vex-mcp@${version} (${TARGETS.length} optional deps pinned)`);

function assertExists(p) {
  if (!existsSync(p)) {
    console.error(`build: expected file not found: ${p}`);
    process.exit(1);
  }
}
