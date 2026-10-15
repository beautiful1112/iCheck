import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {assetCategories,healthEvidenceKey,healthLabel,inventoryPagePath} from '../lib/asset-inventory.ts';

test('inventory categories cover wired, wireless, firewall, hosts and storage',()=>{
  assert.deepEqual(assetCategories.map(([id])=>id),['','wired','wireless','firewalls','servers','storage','other']);
});
test('health labels never turn historical verification into Up',()=>{
  assert.equal(healthLabel('verified'),'Unknown');
  assert.equal(healthLabel('up'),'Up · collecting');
  assert.equal(healthLabel('stale'),'Stale');
  assert.equal(healthLabel('poll_failed'),'Poll failed');
});
test('category filtering and pagination reach the server',()=>{
  const url=new URL(inventoryPagePath('access','wireless','cursor+value'),'https://example.test');
  assert.equal(url.searchParams.get('category'),'wireless');
  assert.equal(url.searchParams.get('cursor'),'cursor+value');
  assert.equal(url.searchParams.get('limit'),'50');
});
test('native and multiple plugin health sources on one connection have distinct render keys',()=>{
  const sources=['Prometheus up','Approved scheduled Collector runtime','Approved scheduled Collector runtime'];
  const keys=sources.map((source,index)=>healthEvidenceKey({connection_id:'same-connection',source},index));
  assert.equal(new Set(keys).size,3);
});
test('default Assets is inventory-first and manual enrollment has its own route',()=>{
  const page=readFileSync(new URL('../app/assets/devices/page.tsx',import.meta.url),'utf8');
  const add=readFileSync(new URL('../app/assets/devices/add/page.tsx',import.meta.url),'utf8');
  const workspace=readFileSync(new URL('../components/assets-workspace.tsx',import.meta.url),'utf8');
  assert.ok(page.includes('mode="inventory"'));
  assert.ok(add.includes('mode="add"'));
  assert.ok(workspace.includes('aria-label="Device categories"'));
  assert.ok(workspace.includes('/assets/devices/health?'));
  assert.ok(workspace.includes('mode === "add" ? <div'));
  assert.ok(workspace.includes('Apply a published monitoring template'));
  assert.ok(workspace.includes('Drafts and MIB proposals'));
  assert.ok(workspace.includes('Preview template assignment'));
  assert.ok(workspace.includes('Apply approved template'));
});
