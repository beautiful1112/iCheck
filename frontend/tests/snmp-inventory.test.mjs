import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { deviceDisplayName } from '../lib/device-onboarding.ts';

test('SNMP sysName replaces only an IP placeholder in the display, not an operator alias', () => {
  assert.equal(deviceDisplayName({name:'192.0.2.1',management_ip:'192.0.2.1',discovered_name:'access'}), 'access');
  assert.equal(deviceDisplayName({name:'core-switch',management_ip:'192.0.2.1',discovered_name:'access'}), 'core-switch');
  assert.equal(deviceDisplayName({name:'192.0.2.1',management_ip:'192.0.2.1'}), '192.0.2.1');
});

test('inventory shows discovery, safe diagnostics and a catalog-backed correction action', () => {
  const page = readFileSync(new URL('../components/assets-workspace.tsx', import.meta.url), 'utf8');
  assert.ok(page.includes('SNMP sysName: {device.discovered_name}'));
  assert.ok(page.includes('deviceDisplayName(device)'));
  assert.ok(page.includes('Root cause:'));
  assert.ok(page.includes('/snmp-configuration'));
  const component = readFileSync(new URL('../components/snmp-configuration.tsx', import.meta.url), 'utf8');
  assert.ok(component.includes('/assets/snmp-modules'));
  assert.ok(component.includes('Save modules and reverify'));
  assert.ok(component.includes('Collector adapters are not module names'));
  assert.ok(component.includes('open={catalog.length > 0 && modules.some('));
  assert.ok(!component.includes('dangerouslySetInnerHTML'));
});
