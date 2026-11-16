import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function findMpCmdRun({ platform = process.platform, programData = process.env.ProgramData, programFiles = process.env.ProgramFiles } = {}) {
  if (platform !== 'win32') return null;

  const platformDirectory = path.join(programData || 'C:\\ProgramData', 'Microsoft', 'Windows Defender', 'Platform');
  try {
    const versions = fs.readdirSync(platformDirectory, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort((left, right) => right.localeCompare(left, undefined, { numeric: true }));
    for (const version of versions) {
      const executable = path.join(platformDirectory, version, 'MpCmdRun.exe');
      if (fs.existsSync(executable)) return executable;
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const inboxExecutable = path.join(programFiles || 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe');
  return fs.existsSync(inboxExecutable) ? inboxExecutable : null;
}

export function interpretDefenderScanResult(exitCode, threatDetected) {
  if (threatDetected) return { verdict: 'threat', malicious: 1, suspicious: 0 };
  if (exitCode === 0) return { verdict: 'clean', malicious: 0, suspicious: 0 };
  throw new Error('Microsoft Defender could not verify the file. Check Windows Security and try again.');
}

function runProcess(executable, args, { env = process.env, timeoutMs = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback(value);
    };
    const timeout = setTimeout(() => {
      child.kill();
      finish(reject, new Error('Microsoft Defender scan timed out.'));
    }, timeoutMs);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => finish(reject, error));
    child.on('close', (code) => finish(resolve, { code, stdout, stderr }));
  });
}

async function runPowerShellJson(script, env, failureMessage) {
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const result = await runProcess(powershell, [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
    Buffer.from(script, 'utf16le').toString('base64')
  ], { env });
  if (result.code !== 0) {
    throw new Error(`${failureMessage} ${result.stderr.trim() || 'Check Windows Security and try again.'}`);
  }
  let value;
  try {
    value = JSON.parse(result.stdout.trim());
  } catch {
    throw new Error(`${failureMessage} Microsoft Defender returned unreadable data.`);
  }
  return value;
}

async function assertDefenderEnabled() {
  const script = [
    '$ErrorActionPreference = \'Stop\'',
    '$status = Get-MpComputerStatus -ErrorAction Stop',
    '[PSCustomObject]@{ enabled = [bool]$status.AntivirusEnabled } | ConvertTo-Json -Compress'
  ].join('\n');
  const status = await runPowerShellJson(script, process.env, 'Could not verify Microsoft Defender status.');
  if (status.enabled !== true) throw new Error('Microsoft Defender antivirus is disabled. Enable it in Windows Security or configure VirusTotal.');
}

async function hasDefenderDetection(scanPath) {
  const script = [
    '$ErrorActionPreference = \'Stop\'',
    '$scanPath = $env:VS_SCAN_FILE',
    '$detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {',
    '  ($_.Resources -join "`n").IndexOf($scanPath, [StringComparison]::OrdinalIgnoreCase) -ge 0',
    '})',
    '[PSCustomObject]@{ detected = ($detections.Count -gt 0) } | ConvertTo-Json -Compress'
  ].join('\n');
  const detection = await runPowerShellJson(script, { ...process.env, VS_SCAN_FILE: scanPath }, 'Could not verify Microsoft Defender scan results.');
  if (typeof detection.detected !== 'boolean') throw new Error('Microsoft Defender returned an incomplete scan result.');
  return detection.detected;
}

export async function scanWithWindowsDefender(buffer, filename = '') {
  if (process.platform !== 'win32') throw new Error('Microsoft Defender scanning is available only on Windows.');
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new Error('Choose a non-empty file to scan.');

  const executable = findMpCmdRun();
  if (!executable) throw new Error('Microsoft Defender command-line scanner was not found on this computer.');

  const temporaryDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'virus-scanner-defender-'));
  const extension = path.extname(filename).toLowerCase();
  const safeExtension = /^\.[a-z0-9]{1,10}$/.test(extension) ? extension : '.bin';
  const scanPath = path.join(temporaryDirectory, `uploaded-file${safeExtension}`);
  try {
    await assertDefenderEnabled();
    await fs.promises.writeFile(scanPath, buffer, { flag: 'wx' });
    const scan = await runProcess(executable, ['-Scan', '-ScanType', '3', '-File', scanPath]);
    const threatDetected = await hasDefenderDetection(scanPath);
    return {
      ...interpretDefenderScanResult(scan.code, threatDetected),
      analysisId: null,
      provider: 'Microsoft Defender'
    };
  } finally {
    await fs.promises.rm(temporaryDirectory, { recursive: true, force: true });
  }
}
