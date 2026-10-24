# Repo Cassette solver

이 문제는 인스턴스를 만드는 GitHub 계정의 **private repository**와 Actions
artifact를 사용한다. 인스턴스 OAuth 토큰이 같은 저장소의 artifact를 읽을 수
있어야 한다.

## 준비

`solver/` 디렉터리를 새 private GitHub repository로 push한다.

```bash
cd solver
git init
git add .
git commit -m 'Add solver'
gh repo create repo-cassette-solver --private --source . --push
```

그 후 workflow를 실행한다.

```bash
gh workflow run build.yml --repo OWNER/repo-cassette-solver
RUN_ID=$(gh run list --repo OWNER/repo-cassette-solver --workflow build.yml \
  --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID" --repo OWNER/repo-cassette-solver --exit-status
```

## 실행

artifact를 만든 계정으로 challenge instancer의 GitHub OAuth 로그인을 마친다.
인스턴스는 약 5분만 유지되므로 artifact를 먼저 만들어 두는 편이 안전하다.
인스턴스를 요청한 것과 같은 공인 IP에서 다음을 실행한다.

```bash
python3 solve.py http://repo-archive.chal.hitconctf.com:PORT \
  OWNER/repo-cassette-solver
```

로컬 `gh` 로그인이 없다면 같은 계정의 토큰을 `GH_TOKEN`에 넣어도 된다.

## 취약점 요약

- 약한 repository 검증 때문에 `OWNER/REPO/actions/artifacts/ID/zip`을 GitHub
  REST 경로로 사용할 수 있다.
- Actions artifact v6/v7 생성 레이스로 raw artifact에
  `\x85application/json` MIME 메타데이터를 붙인다.
- JavaScript `trim()`은 U+0085를 제거하지 않아서 서버는 이를 JSON으로
  검사하지 않고 SHA-256만 기록한다.
- Python `strip()`은 U+0085를 제거하므로 postcard 서비스는 같은 응답을
  `application/json`으로 인정한다.
- JSON의 `avatar_url`을 `file:///proc/self/environ`으로 두면 검증된 카드 SVG에
  postcard 컨테이너 환경 변수가 base64로 삽입된다.
