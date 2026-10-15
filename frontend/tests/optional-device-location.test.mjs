import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { eligibleCredentialProfiles, formatDeviceLocation } from '../lib/device-onboarding.ts';

test('blank physical site permits references without discarding worker custody', () => {
  const profiles = [{id:'lab',name:'lab',enabled:true,allowed_adapters:['snmp_exporter'],worker_selector:{site:'LAB'}},
    {id:'disabled',name:'disabled',enabled:false,allowed_adapters:['snmp_exporter'],worker_selector:{site:'LAB'}}];
  assert.deepEqual(eligibleCredentialProfiles(profiles, 'snmp_exporter', '').map(p => p.id), ['lab']);
  assert.deepEqual(profiles[0].worker_selector, {site:'LAB'});
});

test('six-level placement displays without inventing missing levels', () => {
  assert.equal(formatDeviceLocation({zone:'East',building:'DC1',floor:'2',room:'NOC',rack:'R1',height:12}), 'East / DC1 / 2 / NOC / R1 / U12');
  assert.equal(formatDeviceLocation({room:'NOC'}), 'NOC');
  assert.equal(formatDeviceLocation(), '');
});

test('GUI enrollment has optional site, location editor and an inventory receipt link', () => {
  const page = readFileSync(new URL('../components/assets-workspace.tsx', import.meta.url), 'utf8');
  assert.ok(!page.includes('<Input required value={site}'));
  assert.ok(page.includes('site: site.trim() || null'));
  assert.ok(page.includes('request_monitoring: requestMonitoring'));
  assert.ok(page.includes('<DeviceLocationFields value={location}'));
  assert.ok(page.includes('grid grid-cols-1 gap-5 xl:grid-cols-'));
  const receipt = readFileSync(new URL('../components/device-enrollment-result.tsx', import.meta.url), 'utf8');
  assert.ok(receipt.includes('icheck.device-enrollment-receipt/v1'));
  assert.ok(receipt.includes('href="/assets/devices"'));
  assert.ok(receipt.includes('live monitoring is not yet confirmed'));
});
