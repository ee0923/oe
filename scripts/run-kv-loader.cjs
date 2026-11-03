'use strict';

const { readFileSync } = require('node:fs');
const { loadScript } = require('./remote-loader.cjs');

async function main() {
  const policy = JSON.parse(readFileSync(0, 'utf8'));
  const { script, version, sha256 } = await loadScript(policy);
  console.error(`[openeuicc-customize] version=${version} sha256=${sha256}`);
  process.stdout.write(script);
}

main().catch(() => {
  console.error('Remote customization could not be loaded or verified.');
  process.exitCode = 1;
});
