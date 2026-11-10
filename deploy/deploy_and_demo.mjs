import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createClient, chains, createAccount } from 'genlayer-js';

// Setup custom browser User-Agent header across all fetch calls
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const origFetch = globalThis.fetch;
globalThis.fetch = (url, init = {}) => {
  const headers = new Headers(init?.headers || {});
  if (!headers.has('User-Agent')) {
    headers.set('User-Agent', BROWSER_UA);
  }
  return origFetch(url, { ...init, headers });
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const STATE_FILE = path.join(ROOT_DIR, 'deploy', 'state.json');
const MANIFEST_FILE = path.join(ROOT_DIR, 'deploy', 'manifest.json');

const SOURCE_COMMIT = '5d15e8173e5272e78fa5a4ca18dd90e415989d6f';
const GIT_BLOB_HASH = '76fe77ffcb28945afb0913979fb94ddd7f89043c';
const EXPECTED_LOCAL_SHA256 = '91bc3c12f4fa6a55892aee3e1f0f58b2e821cec1b68dee520f0068acbd738b71';
const RUNNER_HASH = 'py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6';
const DOMAIN_TAG = 'http-retry';
const EPOCH_DURATION = 780; // 13 minutes

const BASE_EVIDENCE_URL = `https://raw.githubusercontent.com/khezzed/PrecedentRegistry/${SOURCE_COMMIT}/evidence`;
const e1_url = `${BASE_EVIDENCE_URL}/e1_5xx_retry_policy.txt`;
const e2_url = `${BASE_EVIDENCE_URL}/e2_503_maintenance_carveout.txt`;
const e3_url = `${BASE_EVIDENCE_URL}/e3_429_ratelimit_policy.txt`;
const e4_url = `${BASE_EVIDENCE_URL}/e4_errata_retract_5xx.txt`;
const e5_url = `${BASE_EVIDENCE_URL}/e5_unrelated_recipe.txt`;

const EVIDENCE_INFO = [
  {
    file: 'evidence/e1_5xx_retry_policy.txt',
    size: 165,
    sha256: '9cdd9145d16281f2c63b2856d5c72b93a763c0c6b83693f8947788d20106d47f',
    url: e1_url
  },
  {
    file: 'evidence/e2_503_maintenance_carveout.txt',
    size: 271,
    sha256: 'b9adfaa139a210239e175dea17ba1fe3b4e26651a6de5529d434e697a9674875',
    url: e2_url
  },
  {
    file: 'evidence/e3_429_ratelimit_policy.txt',
    size: 258,
    sha256: '95c107610aa71b2d0bd1dde3ed61cb160d388cd1962bf1d55489cc2d9ce71522',
    url: e3_url
  },
  {
    file: 'evidence/e4_errata_retract_5xx.txt',
    size: 273,
    sha256: '54a88e6f901c5d6489f084fcd51e61b99acd0d257fe70ce1d4b637bb1094b535',
    url: e4_url
  },
  {
    file: 'evidence/e5_unrelated_recipe.txt',
    size: 149,
    sha256: 'cb675e93dcce55394b445e800d5b92707b333f2c1562ac61c23a6380e5691c60',
    url: e5_url
  }
];

function sha256(content) {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

function normalizeReturn(val) {
  if (typeof val === 'string') {
    let s = val.trim();
    if (s.startsWith('"') && s.endsWith('"')) {
      try {
        return JSON.parse(s);
      } catch {
        return s.slice(1, -1);
      }
    }
    return s;
  }
  return val;
}

function loadState() {
  if (fs.existsSync(STATE_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
    } catch {
      return {};
    }
  }
  return {};
}

function saveState(patch) {
  const current = loadState();
  const updated = { ...current, ...patch, updatedAt: new Date().toISOString() };
  fs.writeFileSync(STATE_FILE, JSON.stringify(updated, null, 2), 'utf-8');
  return updated;
}

function createStudioClient(account) {
  return createClient({
    chain: {
      ...chains.studionet,
      rpcUrls: {
        default: {
          http: ['https://studio.genlayer.com/api']
        }
      }
    },
    account
  });
}

async function waitForReceipt(client, txHash, { maxAttempts = 120, intervalMs = 8000, expectSuccess = true } = {}) {
  console.log(`[POLL] Waiting for tx ${txHash} (expectSuccess=${expectSuccess})...`);
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    await new Promise(r => setTimeout(r, intervalMs));
    try {
      const tx = await client.getTransaction({ hash: txHash });
      const statusName = tx.statusName || (tx.consensus_history?.current_status_changes?.includes('FINALIZED') ? 'FINALIZED' : 'PENDING');
      const resultName = tx.result_name || 'UNKNOWN';
      const lr = tx.consensus_data?.leader_receipt?.[0];
      const execResult = lr?.execution_result || 'PENDING';
      const rawPayload = lr?.result?.payload?.readable ?? lr?.result?.payload ?? '';
      const returnPayload = normalizeReturn(rawPayload);
      const stderr = lr?.genvm_result?.stderr || '';
      const votes = tx.consensus_data?.votes || {};

      console.log(`  [Attempt ${attempt}/${maxAttempts}] status=${statusName} result=${resultName} GenVM=${execResult}`);

      if (statusName === 'FINALIZED') {
        const contractAddress = tx.to_address || tx.contract_address || (tx.data && tx.data.contract_address);

        if (expectSuccess && execResult !== 'SUCCESS') {
          throw new Error(`Transaction ${txHash} finalized with GenVM ${execResult} (expected SUCCESS). stderr: ${stderr} payload: ${JSON.stringify(returnPayload)}`);
        }

        return {
          finalized: true,
          status: statusName,
          result: resultName,
          executionResult: execResult,
          returnReadable: returnPayload,
          stderr,
          votes,
          contractAddress,
          tx
        };
      }
    } catch (err) {
      if (err.message && err.message.includes('finalized with GenVM')) {
        throw err;
      }
      console.warn(`  [Poll attempt ${attempt} warning]: ${err.message || err}`);
    }
  }
  throw new Error(`Transaction ${txHash} did not finalize in ${(maxAttempts * intervalMs) / 1000} seconds`);
}

async function readContractWithRetry(client, { address, functionName, args = [] }, retries = 6, delayMs = 3000) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await client.readContract({ address, functionName, args });
    } catch (err) {
      lastErr = err;
      console.warn(`  [readContract ${functionName} attempt ${attempt} warning]: ${err.message || err}`);
      await new Promise(r => setTimeout(r, delayMs * attempt));
    }
  }
  throw lastErr;
}

async function safeWrite(client, { address, functionName, args = [], value = 0n, expectSuccess = true }) {
  let txHash = null;
  let receipt = null;
  let clientError = null;

  try {
    txHash = await client.writeContract({
      address,
      functionName,
      args,
      value
    });
    console.log(`  -> writeContract ${functionName} sent, txHash: ${txHash}`);
  } catch (err) {
    clientError = err;
    console.log(`  -> writeContract ${functionName} direct client error: ${err.message || err}`);
  }

  if (txHash) {
    receipt = await waitForReceipt(client, txHash, { expectSuccess });
  }

  return { txHash, receipt, clientError };
}

async function main() {
  console.log('===============================================================');
  console.log('  PrecedentRegistry: StudioNet Deploy & Live Demo              ');
  console.log('  Contract Commit: ' + SOURCE_COMMIT);
  console.log('  Blob: ' + GIT_BLOB_HASH);
  console.log('===============================================================');

  const state = loadState();

  if (!state.deployerPrivateKey || !state.account2PrivateKey || !state.account3PrivateKey) {
    throw new Error('Private keys not found in state.json!');
  }

  const accountA = createAccount(state.deployerPrivateKey);
  const accountB = createAccount(state.account2PrivateKey);
  const accountC = createAccount(state.account3PrivateKey);

  console.log(`Account A (Author 1 / Deployer): ${accountA.address}`);
  console.log(`Account B (Author 2)           : ${accountB.address}`);
  console.log(`Account C (Author 3)           : ${accountC.address}`);

  const clientA = createStudioClient(accountA);
  const clientB = createStudioClient(accountB);
  const clientC = createStudioClient(accountC);

  const history = state.history || [];
  let onChainSha256 = state.onChainSha256 || '';
  let blobEquality = state.blobEquality || false;

  function updateManifest() {
    const finalState = loadState();
    const finalHistory = finalState.history || [];
    const finalDomainRaw = finalHistory.find(h => h.step === 'S7')?.readBack || finalHistory.find(h => h.step === 'S1')?.readBack || {};

    const manifest = {
      projectName: 'PrecedentRegistry',
      description: 'Evolving technical standard / case-law registry Intelligent Contract on GenLayer StudioNet',
      sourceCommitSha: SOURCE_COMMIT,
      contractPath: 'contracts/precedent_registry.py',
      gitBlobHash: GIT_BLOB_HASH,
      localContractSha256: EXPECTED_LOCAL_SHA256,
      deployedCodeSha256: onChainSha256,
      blobEqualityResult: blobEquality ? 'MATCH (100% byte-for-byte)' : (onChainSha256 ? 'MISMATCH' : 'PENDING'),
      runnerHash: RUNNER_HASH,
      environment: 'StudioNet',
      network: 'studionet',
      rpcUrl: 'https://studio.genlayer.com/api',
      accounts: {
        accountA: {
          role: 'Creator / Author 1 / Deployer',
          address: accountA.address
        },
        accountB: {
          role: 'Author 2',
          address: accountB.address
        },
        accountC: {
          role: 'Author 3',
          address: accountC.address
        }
      },
      probeContract: {
        codePath: 'deploy/probe.py',
        runnerHash: RUNNER_HASH,
        address: probeAddress || state.probeAddress || '',
        deployTx: probeDeployTx || state.probeDeployTx || '',
        setTx: probeSetTx || state.probeSetTx || '',
        verifiedValue: probeVal || state.probeVal || ''
      },
      mainContract: {
        address: mainAddress || state.mainAddress || '',
        deployTx: mainDeployTx || state.mainDeployTx || ''
      },
      evidenceFiles: EVIDENCE_INFO,
      demoDomain: {
        domainTag: DOMAIN_TAG,
        epochDuration: EPOCH_DURATION
      },
      transactions: finalHistory,
      finalDomainState: finalDomainRaw
    };

    fs.writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2), 'utf-8');
    console.log(`Manifest updated: ${MANIFEST_FILE}`);
  }

  function recordStep(item) {
    const idx = history.findIndex(h => h.step === item.step);
    if (idx >= 0) {
      history[idx] = item;
    } else {
      history.push(item);
    }
    saveState({ history });
    updateManifest();
    console.log(`  [RECORDED STEP ${item.step}] ${item.method} | Hash: ${item.hash || 'N/A'} | Status: ${item.status} | Exec: ${item.executionResult}`);
  }

  function getStep(stepId) {
    return history.find(t => String(t.step) === String(stepId));
  }

  // ---------------------------------------------------------------------------
  // STEP B: PROBE CONTRACT VERIFICATION
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP B: PROBE CONTRACT VERIFICATION ---');
  let probeAddress = state.probeAddress;
  let probeDeployTx = state.probeDeployTx;
  let probeSetTx = state.probeSetTx;
  let probeVal = state.probeVal;

  if (!probeAddress) {
    const probePath = path.join(ROOT_DIR, 'deploy', 'probe.py');
    const probeCode = fs.readFileSync(probePath, 'utf-8');
    console.log(`Deploying probe.py (${probeCode.length} bytes)...`);
    probeDeployTx = await clientA.deployContract({ code: probeCode });
    console.log(`Probe Deploy Tx: ${probeDeployTx}`);
    const probeReceipt = await waitForReceipt(clientA, probeDeployTx, { expectSuccess: true });
    probeAddress = probeReceipt.contractAddress;
    saveState({ probeAddress, probeDeployTx });
    console.log(`Probe contract finalized at: ${probeAddress}`);

    console.log('Writing on Probe: set_val("probe_ok")...');
    const setRes = await safeWrite(clientA, {
      address: probeAddress,
      functionName: 'set_val',
      args: ['probe_ok'],
      expectSuccess: true
    });
    probeSetTx = setRes.txHash;
    saveState({ probeSetTx });

    probeVal = await readContractWithRetry(clientA, {
      address: probeAddress,
      functionName: 'get_val',
      args: []
    });
    saveState({ probeVal });
    console.log(`Probe readback get_val: "${probeVal}"`);
    if (probeVal !== 'probe_ok') {
      throw new Error(`Probe check failed: expected 'probe_ok', got '${probeVal}'`);
    }
    console.log('[PASS] Probe verified on StudioNet!');
  } else {
    console.log(`[SKIP] Probe already deployed at: ${probeAddress}`);
  }

  // ---------------------------------------------------------------------------
  // STEP C: DEPLOY PrecedentRegistry & VERIFY BLOB EQUALITY
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP C: DEPLOY PrecedentRegistry & VERIFY BLOB EQUALITY ---');
  let mainAddress = state.mainAddress;
  let mainDeployTx = state.mainDeployTx;

  const mainPath = path.join(ROOT_DIR, 'contracts', 'precedent_registry.py');
  const mainCode = fs.readFileSync(mainPath, 'utf-8');
  const localSha256 = sha256(mainCode);
  console.log(`Local contract path    : ${mainPath}`);
  console.log(`Local contract size    : ${mainCode.length} bytes`);
  console.log(`Git blob hash (sha1)   : ${GIT_BLOB_HASH}`);
  console.log(`Local source sha256    : ${localSha256}`);

  if (localSha256 !== EXPECTED_LOCAL_SHA256) {
    throw new Error(`Local source sha256 mismatch! Expected ${EXPECTED_LOCAL_SHA256}, got ${localSha256}`);
  }

  if (!mainAddress) {
    console.log(`Deploying PrecedentRegistry (${mainCode.length} bytes)...`);
    mainDeployTx = await clientA.deployContract({ code: mainCode });
    console.log(`Main Deploy Tx: ${mainDeployTx}`);
    const mainReceipt = await waitForReceipt(clientA, mainDeployTx, { expectSuccess: true });
    mainAddress = mainReceipt.contractAddress;
    console.log(`Main Contract Finalized at: ${mainAddress}`);
    saveState({ mainAddress, mainDeployTx });
  } else {
    console.log(`[SKIP] Main contract already deployed at: ${mainAddress}`);
  }

  // Fetch deployed on-chain code and verify byte-for-byte equality
  console.log('Fetching deployed code from StudioNet RPC...');
  const onChainCode = await clientA.getContractCode(mainAddress);
  onChainSha256 = sha256(onChainCode);
  console.log(`On-chain code sha256   : ${onChainSha256}`);

  blobEquality = (mainCode === onChainCode) && (localSha256 === onChainSha256);
  console.log(`Byte-for-byte equality : ${blobEquality ? 'MATCH (100% byte-for-byte)' : 'MISMATCH'}`);
  saveState({ onChainSha256, blobEquality });
  updateManifest();
  if (!blobEquality) {
    throw new Error('CRITICAL: Bytecode mismatch against deployed contract!');
  }

  // ---------------------------------------------------------------------------
  // STEP D: LIVE DEMO ON DOMAIN "http-retry"
  // ---------------------------------------------------------------------------
  console.log('\n--- STEP D: LIVE DEMO ON DOMAIN "http-retry" ---');

  // Helper for LLM steps with STOP RULE: allow at most ONE resubmission if MAJORITY_DISAGREE / UNDETERMINED
  async function callLLMStepWithRetry(client, { functionName, args, expectedReturn, stepName, accountLetter, scenario }) {
    console.log(`\n[${stepName}] Calling ${functionName}(${args.map(a => JSON.stringify(a)).join(', ')})...`);
    let res = await safeWrite(client, {
      address: mainAddress,
      functionName,
      args,
      expectSuccess: false
    });

    let returnStr = String(res.receipt?.returnReadable || '');
    let consensusResult = res.receipt?.result || 'UNKNOWN';

    if (consensusResult === 'MAJORITY_DISAGREE' || consensusResult === 'UNDETERMINED') {
      console.warn(`  [Consensus non-agreement in ${stepName}]: ${consensusResult}. Making ONE identical resubmission per STOP RULE...`);
      res = await safeWrite(client, {
        address: mainAddress,
        functionName,
        args,
        expectSuccess: false
      });
      returnStr = String(res.receipt?.returnReadable || '');
      consensusResult = res.receipt?.result || 'UNKNOWN';
    }

    console.log(`  [${stepName}] Return string: "${returnStr}" (Expected: "${expectedReturn}") | Exec: ${res.receipt?.executionResult}`);

    if (returnStr !== expectedReturn || res.receipt?.executionResult !== 'SUCCESS') {
      console.error(`\nSTOP RULE TRIGGERED in ${stepName}!`);
      console.error(`Expected return: "${expectedReturn}"`);
      console.error(`Actual return  : "${returnStr}"`);
      console.error(`Consensus result: ${consensusResult}`);
      console.error(`Leader stderr  : ${res.receipt?.stderr}`);

      const failedStepRecord = {
        step: stepName,
        scenario,
        method: functionName,
        account: accountLetter,
        args,
        hash: res.txHash,
        status: res.receipt?.status || 'UNKNOWN',
        executionResult: res.receipt?.executionResult || 'ERROR',
        consensusResult,
        returnOrError: returnStr,
        votes: res.receipt?.votes || {},
        expected: expectedReturn,
        actual: returnStr,
        expectedFailure: false,
        readBack: 'STOPPED DUE TO UNEXPECTED JUDGMENT'
      };
      recordStep(failedStepRecord);
      updateManifest();
      process.exit(1);
    }

    return { res, returnStr, consensusResult };
  }

  // ===========================================================================
  // S1 (Account A): open_domain("http-retry", 780)
  // ===========================================================================
  let stepS1 = getStep('S1');
  if (!stepS1) {
    console.log('\n[S1] Account A: open_domain("http-retry", 780)...');
    const res = await safeWrite(clientA, {
      address: mainAddress,
      functionName: 'open_domain',
      args: [DOMAIN_TAG, EPOCH_DURATION],
      expectSuccess: true
    });
    const returnStr = String(res.receipt?.returnReadable || '');
    const expected = 'OPENED:http-retry';
    if (returnStr !== expected) {
      throw new Error(`S1 failed: expected '${expected}', got '${returnStr}'`);
    }

    const domainRaw = await readContractWithRetry(clientA, {
      address: mainAddress,
      functionName: 'get_domain',
      args: [DOMAIN_TAG]
    });
    const domainData = JSON.parse(domainRaw);
    console.log('Domain read-back:', domainData);

    stepS1 = {
      step: 'S1',
      scenario: 'Domain Initialization',
      method: 'open_domain',
      account: 'A',
      args: [DOMAIN_TAG, EPOCH_DURATION],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult: res.receipt.result,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected,
      actual: returnStr,
      expectedFailure: false,
      readBack: domainData
    };
    recordStep(stepS1);
  } else {
    console.log(`[SKIP] S1 already executed: ${stepS1.hash}`);
  }

  // ===========================================================================
  // S2 (Account A): propose_entry("http-retry", "5xx-responses", rule, e1_url, 0)
  // ===========================================================================
  let stepS2 = getStep('S2');
  if (!stepS2) {
    const rule1 = 'All HTTP 5xx server error responses must be retried up to 3 times using exponential backoff.';
    const expected2 = 'ADMITTED:ENTRY_1:RELATION_INITIAL';
    const { res, returnStr, consensusResult } = await callLLMStepWithRetry(clientA, {
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, '5xx-responses', rule1, e1_url, 0],
      expectedReturn: expected2,
      stepName: 'S2',
      accountLetter: 'A',
      scenario: 'Initial Root Precedent Admission'
    });

    const entry1Raw = await readContractWithRetry(clientA, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [1]
    });
    const entry1 = JSON.parse(entry1Raw);
    const activeCanonRaw = await readContractWithRetry(clientA, {
      address: mainAddress,
      functionName: 'get_active_canon',
      args: [DOMAIN_TAG]
    });
    const activeCanon = JSON.parse(activeCanonRaw);

    stepS2 = {
      step: 'S2',
      scenario: 'Initial Root Precedent Admission',
      method: 'propose_entry',
      account: 'A',
      args: [DOMAIN_TAG, '5xx-responses', rule1, e1_url, 0],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: expected2,
      actual: returnStr,
      expectedFailure: false,
      readBack: { entry1, activeCanon }
    };
    recordStep(stepS2);
  } else {
    console.log(`[SKIP] S2 already executed: ${stepS2.hash}`);
  }

  // ===========================================================================
  // S3 (Account B): Path-Dependence / Root Contradiction Blocked
  // ===========================================================================
  let stepS3 = getStep('S3');
  if (!stepS3) {
    const rule2_contradict = 'HTTP 503 responses carrying header X-Maintenance-Window must never be retried.';
    const expected3 = 'REJECTED:FETCH_OK:PREMISE_SUPPORTED:RELATION_CONTRADICTS';
    const { res, returnStr, consensusResult } = await callLLMStepWithRetry(clientB, {
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, '5xx-responses', rule2_contradict, e2_url, 0],
      expectedReturn: expected3,
      stepName: 'S3',
      accountLetter: 'B',
      scenario: 'Path-Dependence / Root Contradiction Blocked'
    });

    const entryCount = await readContractWithRetry(clientB, {
      address: mainAddress,
      functionName: 'get_entry_count',
      args: []
    });
    const activeCanonRaw = await readContractWithRetry(clientB, {
      address: mainAddress,
      functionName: 'get_active_canon',
      args: [DOMAIN_TAG]
    });
    const activeCanon = JSON.parse(activeCanonRaw);

    stepS3 = {
      step: 'S3',
      scenario: 'Path-Dependence / Root Contradiction Blocked',
      method: 'propose_entry',
      account: 'B',
      args: [DOMAIN_TAG, '5xx-responses', rule2_contradict, e2_url, 0],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: expected3,
      actual: returnStr,
      expectedFailure: false, // finalized SUCCESS with contract-level rejection
      readBack: { entryCount, activeCanonCount: activeCanon.length, activeCanon }
    };
    recordStep(stepS3);
  } else {
    console.log(`[SKIP] S3 already executed: ${stepS3.hash}`);
  }

  // ===========================================================================
  // S4 (Account B): Narrowing Carve-Out Admitted
  // ===========================================================================
  let stepS4 = getStep('S4');
  if (!stepS4) {
    const rule2_carveout = 'HTTP 503 responses carrying header X-Maintenance-Window must never be retried, carving out maintenance windows from general 5xx retries.';
    const expected4 = 'ADMITTED:ENTRY_2:RELATION_NARROWS';
    const { res, returnStr, consensusResult } = await callLLMStepWithRetry(clientB, {
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, '503-maintenance', rule2_carveout, e2_url, 1],
      expectedReturn: expected4,
      stepName: 'S4',
      accountLetter: 'B',
      scenario: 'Narrowing Carve-Out Admitted'
    });

    const entry1Raw = await readContractWithRetry(clientB, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [1]
    });
    const entry2Raw = await readContractWithRetry(clientB, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [2]
    });
    const entry1 = JSON.parse(entry1Raw);
    const entry2 = JSON.parse(entry2Raw);

    stepS4 = {
      step: 'S4',
      scenario: 'Narrowing Carve-Out Admitted',
      method: 'propose_entry',
      account: 'B',
      args: [DOMAIN_TAG, '503-maintenance', rule2_carveout, e2_url, 1],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: expected4,
      actual: returnStr,
      expectedFailure: false,
      readBack: { parentEntry1: entry1, childEntry2: entry2 }
    };
    recordStep(stepS4);
  } else {
    console.log(`[SKIP] S4 already executed: ${stepS4.hash}`);
  }

  // ===========================================================================
  // S5 (Account C): Orthogonal Root Admitted
  // ===========================================================================
  let stepS5 = getStep('S5');
  if (!stepS5) {
    const rule3 = 'HTTP 429 Too Many Requests responses must pause and wait for the duration in the Retry-After header.';
    const expected5 = 'ADMITTED:ENTRY_3:RELATION_ORTHOGONAL';
    const { res, returnStr, consensusResult } = await callLLMStepWithRetry(clientC, {
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, '429-rate-limit', rule3, e3_url, 0],
      expectedReturn: expected5,
      stepName: 'S5',
      accountLetter: 'C',
      scenario: 'Orthogonal Root Admitted'
    });

    const entry3Raw = await readContractWithRetry(clientC, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [3]
    });
    const entry3 = JSON.parse(entry3Raw);
    const activeCanonRaw = await readContractWithRetry(clientC, {
      address: mainAddress,
      functionName: 'get_active_canon',
      args: [DOMAIN_TAG]
    });
    const activeCanon = JSON.parse(activeCanonRaw);

    stepS5 = {
      step: 'S5',
      scenario: 'Orthogonal Root Admitted',
      method: 'propose_entry',
      account: 'C',
      args: [DOMAIN_TAG, '429-rate-limit', rule3, e3_url, 0],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: expected5,
      actual: returnStr,
      expectedFailure: false,
      readBack: { entry3, activeCanonCount: activeCanon.length, activeCanon }
    };
    recordStep(stepS5);
  } else {
    console.log(`[SKIP] S5 already executed: ${stepS5.hash}`);
  }

  // ===========================================================================
  // X1 (Account B): Expected Failure: Unrelated Evidence Rejected
  // ===========================================================================
  let stepX1 = getStep('X1');
  if (!stepX1) {
    const rule_unrelated = 'All socket timeouts must default to 5 seconds.';
    const expectedX1 = 'REJECTED:FETCH_OK:PREMISE_UNSUPPORTED:RELATION_UNCLEAR';
    const { res, returnStr, consensusResult } = await callLLMStepWithRetry(clientB, {
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, 'timeout-policy', rule_unrelated, e5_url, 0],
      expectedReturn: expectedX1,
      stepName: 'X1',
      accountLetter: 'B',
      scenario: 'Expected Failure: Unrelated Evidence Rejected'
    });

    const entryCount = await readContractWithRetry(clientB, {
      address: mainAddress,
      functionName: 'get_entry_count',
      args: []
    });

    stepX1 = {
      step: 'X1',
      scenario: 'Expected Failure: Unrelated Evidence Rejected',
      method: 'propose_entry',
      account: 'B',
      args: [DOMAIN_TAG, 'timeout-policy', rule_unrelated, e5_url, 0],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: expectedX1,
      actual: returnStr,
      expectedFailure: true,
      readBack: { entryCount, rejectedAsExpected: true }
    };
    recordStep(stepX1);
  } else {
    console.log(`[SKIP] X1 already executed: ${stepX1.hash}`);
  }

  // ===========================================================================
  // X2 (Account B): Expected Failure: Duplicate Replay Blocked
  // ===========================================================================
  let stepX2 = getStep('X2');
  if (!stepX2) {
    console.log('\n[X2] Account B: Exact replay of S4 (expect REPLAY_SUBMISSION)...');
    const rule2_carveout = 'HTTP 503 responses carrying header X-Maintenance-Window must never be retried, carving out maintenance windows from general 5xx retries.';
    const res = await safeWrite(clientB, {
      address: mainAddress,
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, '503-maintenance', rule2_carveout, e2_url, 1],
      expectSuccess: false
    });

    const errStr = res.clientError?.message || res.receipt?.stderr || JSON.stringify(res.receipt?.returnReadable);
    console.log('  Replay error received:', errStr);
    if (!errStr.includes('REPLAY_SUBMISSION')) {
      console.error('STOP RULE: X2 did not fail with REPLAY_SUBMISSION!');
      process.exit(1);
    }

    stepX2 = {
      step: 'X2',
      scenario: 'Expected Failure: Duplicate Replay Blocked',
      method: 'propose_entry',
      account: 'B',
      args: [DOMAIN_TAG, '503-maintenance', rule2_carveout, e2_url, 1],
      hash: res.txHash,
      status: res.receipt?.status || 'LOCAL_CLIENT_REJECTED',
      executionResult: res.receipt?.executionResult || 'ERROR',
      consensusResult: res.receipt?.result || 'N/A',
      returnOrError: errStr,
      votes: res.receipt?.votes || {},
      expected: 'UserError: REPLAY_SUBMISSION',
      actual: errStr,
      expectedFailure: true,
      readBack: 'Duplicate proposal blocked by replay key cache'
    };
    recordStep(stepX2);
  } else {
    console.log(`[SKIP] X2 already executed: ${stepX2.hash}`);
  }

  // ===========================================================================
  // X3 (Account C): Expected Failure: Unauthorized Retraction Blocked
  // ===========================================================================
  let stepX3 = getStep('X3');
  if (!stepX3) {
    console.log('\n[X3] Account C: retract_entry(1, e4_url) (expect UNAUTHORIZED_RETRACTION)...');
    const res = await safeWrite(clientC, {
      address: mainAddress,
      functionName: 'retract_entry',
      args: [1, e4_url],
      expectSuccess: false
    });

    const errStr = res.clientError?.message || res.receipt?.stderr || JSON.stringify(res.receipt?.returnReadable);
    console.log('  Unauthorized error received:', errStr);
    if (!errStr.includes('UNAUTHORIZED_RETRACTION')) {
      console.error('STOP RULE: X3 did not fail with UNAUTHORIZED_RETRACTION!');
      process.exit(1);
    }

    stepX3 = {
      step: 'X3',
      scenario: 'Expected Failure: Unauthorized Retraction Blocked',
      method: 'retract_entry',
      account: 'C',
      args: [1, e4_url],
      hash: res.txHash,
      status: res.receipt?.status || 'LOCAL_CLIENT_REJECTED',
      executionResult: res.receipt?.executionResult || 'ERROR',
      consensusResult: res.receipt?.result || 'N/A',
      returnOrError: errStr,
      votes: res.receipt?.votes || {},
      expected: 'UserError: UNAUTHORIZED_RETRACTION',
      actual: errStr,
      expectedFailure: true,
      readBack: 'Non-author retraction blocked'
    };
    recordStep(stepX3);
  } else {
    console.log(`[SKIP] X3 already executed: ${stepX3.hash}`);
  }

  // ===========================================================================
  // X4 (Account B): Expected Failure: Unpinned URL Blocked
  // ===========================================================================
  let stepX4 = getStep('X4');
  if (!stepX4) {
    console.log('\n[X4] Account B: Unpinned evidence URL with /main/ (expect INVALID_EVIDENCE_URL)...');
    const unpinnedUrl = 'https://raw.githubusercontent.com/khezzed/PrecedentRegistry/main/evidence/e1_5xx_retry_policy.txt';
    const res = await safeWrite(clientB, {
      address: mainAddress,
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, 'dns-cache', 'Cache DNS for 60s.', unpinnedUrl, 0],
      expectSuccess: false
    });

    const errStr = res.clientError?.message || res.receipt?.stderr || JSON.stringify(res.receipt?.returnReadable);
    console.log('  Invalid URL error received:', errStr);
    if (!errStr.includes('INVALID_EVIDENCE_URL')) {
      console.error('STOP RULE: X4 did not fail with INVALID_EVIDENCE_URL!');
      process.exit(1);
    }

    stepX4 = {
      step: 'X4',
      scenario: 'Expected Failure: Unpinned URL Blocked',
      method: 'propose_entry',
      account: 'B',
      args: [DOMAIN_TAG, 'dns-cache', 'Cache DNS for 60s.', unpinnedUrl, 0],
      hash: res.txHash,
      status: res.receipt?.status || 'LOCAL_CLIENT_REJECTED',
      executionResult: res.receipt?.executionResult || 'ERROR',
      consensusResult: res.receipt?.result || 'N/A',
      returnOrError: errStr,
      votes: res.receipt?.votes || {},
      expected: 'UserError: INVALID_EVIDENCE_URL',
      actual: errStr,
      expectedFailure: true,
      readBack: 'Unpinned mutable git branch URL blocked'
    };
    recordStep(stepX4);
  } else {
    console.log(`[SKIP] X4 already executed: ${stepX4.hash}`);
  }

  // ===========================================================================
  // X5 (Account A): Expected Failure: Premature Epoch Freeze Blocked
  // ===========================================================================
  let stepX5 = getStep('X5');
  if (!stepX5) {
    console.log('\n[X5] Account A: freeze_epoch before deadline (expect EPOCH_NOT_READY)...');
    const res = await safeWrite(clientA, {
      address: mainAddress,
      functionName: 'freeze_epoch',
      args: [DOMAIN_TAG],
      expectSuccess: false
    });

    const errStr = res.clientError?.message || res.receipt?.stderr || JSON.stringify(res.receipt?.returnReadable);
    console.log('  Premature freeze error received:', errStr);
    if (!errStr.includes('EPOCH_NOT_READY')) {
      console.error('STOP RULE: X5 did not fail with EPOCH_NOT_READY!');
      process.exit(1);
    }

    stepX5 = {
      step: 'X5',
      scenario: 'Expected Failure: Premature Epoch Freeze Blocked',
      method: 'freeze_epoch',
      account: 'A',
      args: [DOMAIN_TAG],
      hash: res.txHash,
      status: res.receipt?.status || 'LOCAL_CLIENT_REJECTED',
      executionResult: res.receipt?.executionResult || 'ERROR',
      consensusResult: res.receipt?.result || 'N/A',
      returnOrError: errStr,
      votes: res.receipt?.votes || {},
      expected: 'UserError: EPOCH_NOT_READY',
      actual: errStr,
      expectedFailure: true,
      readBack: 'Premature freeze before epoch deadline blocked'
    };
    recordStep(stepX5);
  } else {
    console.log(`[SKIP] X5 already executed: ${stepX5.hash}`);
  }

  // ===========================================================================
  // S6 (Account A): Parent Retraction + Deterministic Cascade to Child
  // ===========================================================================
  let stepS6 = getStep('S6');
  if (!stepS6) {
    const expected6 = 'RETRACTED:ENTRY_1:ORPHANED_1';
    const { res, returnStr, consensusResult } = await callLLMStepWithRetry(clientA, {
      functionName: 'retract_entry',
      args: [1, e4_url],
      expectedReturn: expected6,
      stepName: 'S6',
      accountLetter: 'A',
      scenario: 'Parent Retraction + Deterministic Cascade to Child'
    });

    const entry1Raw = await readContractWithRetry(clientA, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [1]
    });
    const entry2Raw = await readContractWithRetry(clientA, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [2]
    });
    const entry3Raw = await readContractWithRetry(clientA, {
      address: mainAddress,
      functionName: 'get_entry',
      args: [3]
    });
    const entry1 = JSON.parse(entry1Raw);
    const entry2 = JSON.parse(entry2Raw);
    const entry3 = JSON.parse(entry3Raw);

    console.log('Read-back after S6:');
    console.log('  Entry 1 status:', entry1.status, '(retraction_digest set:', !!entry1.retraction_digest, ')');
    console.log('  Entry 2 status:', entry2.status);
    console.log('  Entry 3 status:', entry3.status);

    if (entry1.status !== 'RETRACTED' || entry2.status !== 'ORPHANED_BY_PARENT' || entry3.status !== 'ACTIVE') {
      console.error('STOP RULE: Cascade status mismatch in S6 read-back!');
      process.exit(1);
    }

    stepS6 = {
      step: 'S6',
      scenario: 'Parent Retraction + Deterministic Cascade to Child',
      method: 'retract_entry',
      account: 'A',
      args: [1, e4_url],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: expected6,
      actual: returnStr,
      expectedFailure: false,
      readBack: { entry1, entry2, entry3 }
    };
    recordStep(stepS6);
  } else {
    console.log(`[SKIP] S6 already executed: ${stepS6.hash}`);
  }

  // ===========================================================================
  // X6 (Account B): Expected Failure: Carve-out on Orphaned/Retracted Parent Blocked
  // ===========================================================================
  let stepX6 = getStep('X6');
  if (!stepX6) {
    console.log('\n[X6] Account B: propose_entry targeting orphaned Entry 2 (expect PARENT_NOT_ACTIVE)...');
    const res = await safeWrite(clientB, {
      address: mainAddress,
      functionName: 'propose_entry',
      args: [DOMAIN_TAG, '503-sub', 'Never retry 503 on gateway.', e2_url, 2],
      expectSuccess: false
    });

    const errStr = res.clientError?.message || res.receipt?.stderr || JSON.stringify(res.receipt?.returnReadable);
    console.log('  Orphaned parent error received:', errStr);
    if (!errStr.includes('PARENT_NOT_ACTIVE')) {
      console.error('STOP RULE: X6 did not fail with PARENT_NOT_ACTIVE!');
      process.exit(1);
    }

    stepX6 = {
      step: 'X6',
      scenario: 'Expected Failure: Carve-out on Orphaned/Retracted Parent Blocked',
      method: 'propose_entry',
      account: 'B',
      args: [DOMAIN_TAG, '503-sub', 'Never retry 503 on gateway.', e2_url, 2],
      hash: res.txHash,
      status: res.receipt?.status || 'LOCAL_CLIENT_REJECTED',
      executionResult: res.receipt?.executionResult || 'ERROR',
      consensusResult: res.receipt?.result || 'N/A',
      returnOrError: errStr,
      votes: res.receipt?.votes || {},
      expected: 'UserError: PARENT_NOT_ACTIVE',
      actual: errStr,
      expectedFailure: true,
      readBack: 'Carve-out targeting orphaned parent prevented'
    };
    recordStep(stepX6);
  } else {
    console.log(`[SKIP] X6 already executed: ${stepX6.hash}`);
  }

  // ===========================================================================
  // WAIT FOR EPOCH DEADLINE
  // ===========================================================================
  console.log('\n--- CHECKING EPOCH DEADLINE FOR DOMAIN "http-retry" ---');
  const domainRawBeforeWait = await readContractWithRetry(clientA, {
    address: mainAddress,
    functionName: 'get_domain',
    args: [DOMAIN_TAG]
  });
  const domainBeforeWait = JSON.parse(domainRawBeforeWait);
  const deadline = parseInt(domainBeforeWait.epoch_deadline, 10);
  console.log(`Domain epoch_deadline: ${deadline} (${new Date(deadline * 1000).toISOString()})`);

  let nowSec = Math.floor(Date.now() / 1000);
  while (nowSec < deadline + 15) {
    const diff = (deadline + 15) - nowSec;
    console.log(`Waiting for epoch deadline to expire... ${diff}s remaining (current time: ${nowSec})`);
    const sleepMs = Math.min(diff * 1000, 20000);
    await new Promise(r => setTimeout(r, Math.max(sleepMs, 5000)));
    nowSec = Math.floor(Date.now() / 1000);
  }
  console.log(`Epoch deadline reached! nowSec=${nowSec} >= deadline=${deadline}`);

  // ===========================================================================
  // S7 (Account C): Permissionless Epoch Freeze
  // ===========================================================================
  let stepS7 = getStep('S7');
  if (!stepS7) {
    console.log('\n[S7] Account C: freeze_epoch("http-retry")...');
    const res = await safeWrite(clientC, {
      address: mainAddress,
      functionName: 'freeze_epoch',
      args: [DOMAIN_TAG],
      expectSuccess: true
    });
    const returnStr = String(res.receipt?.returnReadable || '');
    console.log('Freeze epoch return:', returnStr);

    if (!returnStr.startsWith('FROZEN:EPOCH_1:DIGEST_')) {
      throw new Error(`S7 failed: expected 'FROZEN:EPOCH_1:DIGEST_<digest>', got '${returnStr}'`);
    }

    const domainRawAfterFreeze = await readContractWithRetry(clientC, {
      address: mainAddress,
      functionName: 'get_domain',
      args: [DOMAIN_TAG]
    });
    const domainAfterFreeze = JSON.parse(domainRawAfterFreeze);
    console.log('Domain after freeze:', domainAfterFreeze);

    stepS7 = {
      step: 'S7',
      scenario: 'Permissionless Epoch Freeze',
      method: 'freeze_epoch',
      account: 'C',
      args: [DOMAIN_TAG],
      hash: res.txHash,
      status: res.receipt.status,
      executionResult: res.receipt.executionResult,
      consensusResult: res.receipt.result,
      returnOrError: returnStr,
      votes: res.receipt.votes || {},
      expected: 'FROZEN:EPOCH_1:DIGEST_<canon_digest>',
      actual: returnStr,
      expectedFailure: false,
      readBack: domainAfterFreeze
    };
    recordStep(stepS7);
  } else {
    console.log(`[SKIP] S7 already executed: ${stepS7.hash}`);
  }

  // ===========================================================================
  // X7 (Account A): Expected Failure: Double Freeze Blocked
  // ===========================================================================
  let stepX7 = getStep('X7');
  if (!stepX7) {
    console.log('\n[X7] Account A: freeze_epoch again (expect DOMAIN_ALREADY_FROZEN)...');
    const res = await safeWrite(clientA, {
      address: mainAddress,
      functionName: 'freeze_epoch',
      args: [DOMAIN_TAG],
      expectSuccess: false
    });

    const errStr = res.clientError?.message || res.receipt?.stderr || JSON.stringify(res.receipt?.returnReadable);
    console.log('  Double freeze error received:', errStr);
    if (!errStr.includes('DOMAIN_ALREADY_FROZEN')) {
      console.error('STOP RULE: X7 did not fail with DOMAIN_ALREADY_FROZEN!');
      process.exit(1);
    }

    stepX7 = {
      step: 'X7',
      scenario: 'Expected Failure: Double Freeze Blocked',
      method: 'freeze_epoch',
      account: 'A',
      args: [DOMAIN_TAG],
      hash: res.txHash,
      status: res.receipt?.status || 'LOCAL_CLIENT_REJECTED',
      executionResult: res.receipt?.executionResult || 'ERROR',
      consensusResult: res.receipt?.result || 'N/A',
      returnOrError: errStr,
      votes: res.receipt?.votes || {},
      expected: 'UserError: DOMAIN_ALREADY_FROZEN',
      actual: errStr,
      expectedFailure: true,
      readBack: 'Double freeze prevented'
    };
    recordStep(stepX7);
  } else {
    console.log(`[SKIP] X7 already executed: ${stepX7.hash}`);
  }

  updateManifest();
  console.log('\n===============================================================');
  console.log('  ALL STEPS COMPLETED SUCCESSFULLY!                            ');
  console.log('  Manifest written to deploy/manifest.json                     ');
  console.log('===============================================================');
}

main().catch(err => {
  console.error('\nFATAL ERROR in deploy_and_demo:', err);
  process.exit(1);
});
