// Shared adversarial fixtures must agree with the pinned upstream ledger contract.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const upstream = require('../third_party/cloudflare-security-audit/security-audit/validate-coverage-ledger.cjs');
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/source-audit-coverage.json'), 'utf8'));
for (const fixture of cases) {
  const errors = upstream.validateDocument(fixture.ledger);
  assert.equal(errors.length === 0, fixture.valid, fixture.name + ': ' + errors.join('; '));
}
console.log(`PASS: ${cases.length} shared coverage fixtures agree with pinned upstream validator`);
