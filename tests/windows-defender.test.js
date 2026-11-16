import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { findMpCmdRun, interpretDefenderScanResult } from '../windows-defender.js';

test('Defender scanner is unavailable on non-Windows hosts', () => {
  assert.equal(findMpCmdRun({ platform: 'linux' }), null);
});

test('finds the newest installed Defender platform scanner', () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'defender-path-test-'));
  try {
    const platformDirectory = path.join(temporaryRoot, 'Microsoft', 'Windows Defender', 'Platform');
    const olderExecutable = path.join(platformDirectory, '4.18.9', 'MpCmdRun.exe');
    const newerExecutable = path.join(platformDirectory, '4.18.10', 'MpCmdRun.exe');
    fs.mkdirSync(path.dirname(olderExecutable), { recursive: true });
    fs.mkdirSync(path.dirname(newerExecutable), { recursive: true });
    fs.writeFileSync(olderExecutable, '');
    fs.writeFileSync(newerExecutable, '');

    assert.equal(findMpCmdRun({ platform: 'win32', programData: temporaryRoot, programFiles: temporaryRoot }), newerExecutable);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('a Defender detection is a threat even when Defender remediates it', () => {
  assert.deepEqual(interpretDefenderScanResult(0, true), { verdict: 'threat', malicious: 1, suspicious: 0 });
});

test('a completed scan with no detection is clean', () => {
  assert.deepEqual(interpretDefenderScanResult(0, false), { verdict: 'clean', malicious: 0, suspicious: 0 });
});

test('a failed scan is never reported as clean', () => {
  assert.throws(() => interpretDefenderScanResult(2, false), /could not verify the file/);
});
