#!/usr/bin/env node
'use strict';

// Research-only oracle. Execute the ACTUAL Gladys controller file at the exact
// upstream commit with dependency adapters, and real reads within mkdtemp.
// No HTTP server, external filesystem path or real secret is accessed.
// Controller body is NEVER reimplemented or modified.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { Writable } = require('node:stream');

const phase = process.argv[2];
const upstream = process.argv[3];
if (!['before', 'after'].includes(phase) || !upstream || !fs.statSync(upstream).isDirectory()) {
  process.stderr.write('usage: node gladys_original_stream_witness.js before|after UPSTREAM_TREE\n');
  process.exit(2);
}

class Error400 extends Error { constructor(message) { super(message); this.name = 'Error400'; this.status = 400; } }
class Error404 extends Error { constructor(message) { super(message); this.name = 'Error404'; this.status = 404; } }

function loadExactOriginalController(tree, safeRoot) {
  const controllerPath = path.join(tree, 'server/services/rtsp-camera/api/rtspCamera.controller.js');
  const validatorsPath = path.join(tree, 'server/services/rtsp-camera/utils/validateStreamParams.js');
  assert.ok(fs.statSync(controllerPath).isFile());
  const controllerText = fs.readFileSync(controllerPath, 'utf8');

  // Use real fs streams, with an additional harness-only confinement boundary.
  // A traversal from the streaming root into the same isolated temp root
  // remains observable, without permitting host filesystem access.
  const safeFs = Object.freeze({
    createReadStream(p) {
      const resolved = path.resolve(p);
      assert.ok(resolved.startsWith(safeRoot + path.sep), 'ORACLE_ESCAPED_ITS_TEST_SANDBOX');
      return fs.createReadStream(resolved);
    },
  });

  const validationModule = { exports: {} };
  function originalRequire(name) {
    if (name === 'fs') return safeFs;
    if (name === 'path') return path;
    if (name === '../../../utils/logger') return { warn() {} };
    if (name === '../../../utils/httpErrors') return { Error400, Error404 };
    if (name === '../../../api/middlewares/asyncMiddleware') return fn => fn;
    if (name === '../utils/validateStreamParams') {
      const original = fs.readFileSync(validatorsPath, 'utf8');
      vm.runInNewContext(original, {
        require(target) {
          assert.equal(target, '../../../utils/httpErrors', 'UNKNOWN_VALIDATOR_DEPENDENCY');
          return { Error400, Error404 };
        },
        module: validationModule,
      }, { filename: validatorsPath, timeout: 1000 });
      return validationModule.exports;
    }
    throw new Error('UNKNOWN_CONTROLLER_DEPENDENCY: ' + name);
  }
  const controllerModule = { exports: {} };
  vm.runInNewContext(controllerText, {
    require: originalRequire, module: controllerModule,
  }, { filename: controllerPath, timeout: 1000 });
  assert.equal(typeof controllerModule.exports, 'function');
  return controllerModule.exports;
}

async function invoke(controller, params) {
  const chunks = [];
  const response = new Writable({
    write(chunk, encoding, done) { chunks.push(Buffer.from(chunk)); done(); },
  });
  response.status = () => response;
  let resolveFinish, rejectFinish;
  const done = new Promise((resolve, reject) => { resolveFinish = resolve; rejectFinish = reject; });
  response.once('finish', resolveFinish);
  response.once('error', rejectFinish);

  const route = controller['get /api/v1/service/rtsp-camera/camera/streaming/:folder/:file'];
  assert.equal(route.authenticated, true);
  assert.equal(route.admin, false);
  try {
    await route.controller({ params }, response);
  } catch (e) {
    assert.equal(chunks.length, 0);
    return { error: e };
  }
  await Promise.race([
    done,
    new Promise((_, reject) => setTimeout(() => reject(new Error('STREAM_TIMEOUT')), 5000)),
  ]);
  return { body: Buffer.concat(chunks).toString('utf8') };
}

async function main() {
  const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ultrasec-gladys-'));
  try {
    const streamFolder = path.join(testRoot, 'streams');
    fs.mkdirSync(path.join(streamFolder, 'camera-test'), { recursive: true });
    const canary = 'PUBLIC_SYNTHETIC_CANARY_NO_SECRET';
    fs.writeFileSync(path.join(testRoot, 'canary.txt'), canary);
    fs.writeFileSync(path.join(streamFolder, 'camera-test/index.m3u8'), 'LOCAL_HLS_PLAYLIST');
    fs.writeFileSync(path.join(streamFolder, 'camera-test/index1.ts'), 'LOCAL_HLS_CHUNK');
    const create = loadExactOriginalController(path.resolve(upstream), testRoot);
    const controller = create({ config: { tempFolder: streamFolder } }, {});

    // CVE oracle: authenticated route may escape configured streaming temp root
    // and read a file in the adjacent isolated directory in the BEFORE commit.
    const traversal = await invoke(controller, { folder: '..', file: 'canary.txt' });
    if (phase === 'before') {
      assert.equal(traversal.body, canary);
      process.stdout.write('BEFORE_CANARY_READ_CONFIRMED=true\n');
    } else {
      assert.equal(traversal.error?.status, 400);
      assert.equal(traversal.body, undefined);
      process.stdout.write('AFTER_PATH_TRAVERSAL_REJECTED=true\n');
    }

    const normal = await invoke(controller, { folder: 'camera-test', file: 'index.m3u8' });
    assert.equal(normal.body, 'LOCAL_HLS_PLAYLIST');
    process.stdout.write('NEGATIVE_VALID_STREAM_PASS=true\n');

    const chunk = await invoke(controller, { folder: 'camera-test', file: 'index1.ts' });
    assert.equal(chunk.body, 'LOCAL_HLS_CHUNK');
    process.stdout.write('NEGATIVE_VALID_TS_PASS=true\n');

    process.stdout.write('NO_EXTERNAL_IO=true\n');
    process.stdout.write('NATIVE_SCOPE=ORIGINAL_CONTROLLER_WITH_ISOLATED_DEPENDENCY_ADAPTERS\n');
    process.stdout.write('HOLDOUT=UNASSIGNED\nGOLD_ADMITTED=0\n');
  } finally {
    fs.rmSync(testRoot, { recursive: true, force: true });
  }
}

main().catch(e => {
  process.stderr.write('ORIGINAL_WITNESS_FAIL_CLOSED=' + (e?.message || String(e)) + '\n');
  process.exitCode = 1;
});
