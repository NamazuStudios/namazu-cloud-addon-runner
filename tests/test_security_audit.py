"""Tests for the automatic AI security audit (security_audit.py): the
deterministic machine pass (statement extraction, fixed checks, diff-based
trust-narrowing), the agent merge guard (the agent cannot invent files or
permissions), report rendering, sticky-comment upsert, and exit codes.
Bedrock is faked at the boto3 seam — no network in tests."""

import json

import pytest

import security_audit as sa


# ----------------------------------------------------------------- fixtures --

TF = '''
resource "aws_s3_bucket" "artifacts" {
  bucket = "tenant-artifacts"
}

data "aws_iam_policy_document" "readonly" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::tenant-artifacts", "arn:aws:s3:::tenant-artifacts/*"]
  }
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "worker" {
  name = "worker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
    }]
  })
}

resource "aws_iam_role_policy" "escalate" {
  name = "escalate"
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "sts:AssumeRole"]
      Resource = ["arn:aws:iam::123456789012:role/target"]
    }]
  })
}
'''


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "tf").mkdir(parents=True)
    (root / "tf" / "main.tf").write_text(TF)
    return root


def statements_from(repo):
    text = (repo / "tf" / "main.tf").read_text()
    return sa.extract_statements("tf/main.tf", text)


# ---------------------------------------------------------------- extraction --

def test_extract_identity_and_trust(repo):
    stmts = statements_from(repo)
    identity = [s for s in stmts if s.kind == "identity"]
    trust = [s for s in stmts if s.kind == "trust"]
    assert len(identity) == 3 and len(trust) == 1
    ro = identity[0]
    assert "s3:GetObject" in ro.actions
    assert "arn:aws:s3:::tenant-artifacts" in ro.resources
    assert ro.via == "document"
    assert trust[0].principals == ["arn:aws:iam::123456789012:root"]
    assert trust[0].actions == ["sts:AssumeRole"]


def test_extract_lines_are_real(repo):
    text = (repo / "tf" / "main.tf").read_text().splitlines()
    for s in statements_from(repo):
        assert 1 <= s.line <= len(text)
        if s.via == "jsonencode":
            assert "jsonencode" in text[s.line - 1]
        else:
            assert "aws_iam_policy_document" in text[s.line - 1]


def test_extract_heredoc_json(repo):
    heredoc = '''
resource "aws_iam_policy" "pdf" {
  name = "pdf"
  policy = <<POLICY
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}
POLICY
}
'''
    stmts = sa.extract_statements("x.tf", heredoc)
    assert len(stmts) == 1
    assert stmts[0].via == "heredoc"
    assert stmts[0].actions == ["ec2:Describe*"]


# ----------------------------------------------------------- machine findings --

def test_wildcards_and_escalation_flagged(repo):
    stmts = statements_from(repo)
    findings = sa.machine_findings(stmts, {"s3", "iam", "sts"}, {})
    rules = {(f.rule, f.severity) for f in findings}
    assert ("WILDCARD_ACTION", "HIGH") in rules      # blanket "*"
    assert ("WILDCARD_RESOURCE", "HIGH") in rules    # Resource "*"
    assert ("ESCALATION_PRIMITIVE", "HIGH") in rules # iam:PassRole
    assert ("TRUST_ACCOUNT_PRINCIPAL", "MEDIUM") in rules
    assert ("TRUST_NO_CONDITION", "MEDIUM") in rules


def test_wildcard_iam_action_is_high_even_scoped(repo):
    stmts = sa.extract_statements("x.tf", '''
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["iam:*"]
    resources = ["arn:aws:iam::123456789012:role/x"]
  }
}
''')
    findings = sa.machine_findings(stmts, {"iam"}, {})
    assert any(f.rule == "WILDCARD_ACTION" and f.severity == "HIGH"
               for f in findings)


def test_coherence_mismatch(repo):
    stmts = sa.extract_statements("x.tf", '''
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = ["arn:aws:s3:::bucket"]
  }
}
''')
    findings = sa.machine_findings(stmts, {"dynamodb", "s3"}, {})
    assert any(f.rule == "COHERENCE_MISMATCH" for f in findings)


def test_orphan_service_flagged_when_unused(repo):
    stmts = sa.extract_statements("x.tf", '''
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["sns:Publish"]
    resources = ["arn:aws:sns:us-east-1:123456789012:topic"]
  }
}
''')
    findings = sa.machine_findings(stmts, {"s3"}, {})
    assert any(f.rule == "ORPHAN_SERVICE" and "sns" in f.message for f in findings)


def test_no_orphan_when_service_in_use(repo):
    stmts = sa.extract_statements("x.tf", '''
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bucket"]
  }
}
''')
    findings = sa.machine_findings(stmts, {"s3"}, {})
    assert not any(f.rule == "ORPHAN_SERVICE" for f in findings)


def test_trust_narrowing_from_diff():
    diff = "\n".join([
        "diff --git a/tf/trust.tf b/tf/trust.tf",
        "--- a/tf/trust.tf",
        "+++ b/tf/trust.tf",
        '@@ -1,3 +1,2 @@',
        '-      Condition = { StringEquals = { "sts:ExternalId" = "x" } }',
        '+      Principal = { AWS = "arn:aws:iam::999:role/wider" }',
    ])
    assert sa.trust_narrowing(diff) == {"tf/trust.tf": True}


def test_trust_narrowing_ignores_non_tf():
    diff = "diff --git a/docs.md b/docs.md\n--- a/docs.md\n+++ b/docs.md\n-Condition = x\n"
    assert sa.trust_narrowing(diff) == {}


# ---------------------------------------------------------------- agent pass --

class FakeBedrock:
    def __init__(self, payload):
        self.payload = payload

    def converse(self, **kwargs):
        self.kwargs = kwargs
        return {"usage": {"inputTokens": 101, "outputTokens": 22},
                "output": {"message": {"content": [{"text": self.payload}]}}}


def fake_boto3(monkeypatch, payload):
    calls = {}

    class FakeModule:
        @staticmethod
        def client(service, region_name=None):
            assert service == "bedrock-runtime"
            calls["region"] = region_name
            return FakeBedrock(payload)

    import types
    mod = types.ModuleType("boto3")
    mod.client = staticmethod(lambda service, region_name=None: FakeBedrock(payload).client_visit())
    # simpler: return an object whose client() returns a FakeBedrock instance
    holder = {"instance": None}

    class Client(FakeBedrock):
        pass

    def make_client(service, region_name=None):
        calls["region"] = region_name
        inst = Client(payload)
        holder["instance"] = inst
        return inst

    mod.client = make_client
    monkeypatch.setattr(sa, "boto3", mod)
    return calls, holder


CFG = sa.parse_args([
    "--diff-file", "x", "--out", "x", "--aws-region", "us-east-1",
])


def test_agent_output_parsed_and_guarded(monkeypatch, repo):
    agent_json = json.dumps({
        "summary": "mostly fine",
        "glaring": ["blanket * statement"],
        "findings": [
            {"file": "tf/main.tf", "line": 6, "severity": "HIGH",
             "rule": "WILDCARD_ACTION", "why": "every action everywhere",
             "tighter": "list the two s3 actions actually needed"},
            {"file": "tf/main.tf", "line": 999, "severity": "LOW",
             "rule": "AGENT_NOTE", "why": "worth a look", "tighter": ""},
            {"file": "tf/EVIL.tf", "line": 1, "severity": "HIGH",
             "rule": "INVENTED", "why": "not a real file"},
        ],
    })
    calls, holder = fake_boto3(monkeypatch, agent_json)
    stmts = statements_from(repo)
    machine = sa.machine_findings(stmts, {"s3", "iam", "sts"}, {})
    texts = {"tf/main.tf": (repo / "tf" / "main.tf").read_text()}
    parsed, usage = sa.agent_review(CFG, texts, stmts, machine,
                                    {"title": "t", "body": ""}, list(texts))
    assert usage["outputTokens"] == 22
    assert parsed["summary"] == "mostly fine"
    # the guard: the invented file never survives
    assert all(f["file"] in texts for f in parsed["findings"])
    merged = sa.merge_findings(machine, parsed)
    # same rule+file+line as a machine finding MERGES (no duplicate)
    wildcards = [f for f in merged if f.rule == "WILDCARD_ACTION"]
    assert len(wildcards) == 1
    assert "every action everywhere" in wildcards[0].message
    assert wildcards[0].tighter == "list the two s3 actions actually needed"
    # a distinct key is a genuine addition with agent origin
    assert any(f.origin == "agent" and f.rule == "AGENT_NOTE"
               for f in merged)


def test_over_budget_ships_machine_only(monkeypatch, repo):
    calls, holder = fake_boto3(monkeypatch, "{}")
    cfg = sa.parse_args([
        "--diff-file", "x", "--out", "x", "--aws-region", "us-east-1",
        "--token-budget", "1",
    ])
    stmts = statements_from(repo)
    parsed, usage = sa.agent_review(cfg, {"tf/main.tf": TF}, stmts, [],
                                    {}, ["tf/main.tf"])
    assert parsed is None
    assert holder["instance"] is None  # never called


def test_agent_failure_degrades(monkeypatch, repo):
    def boom(*a, **k):
        raise RuntimeError("bedrock down")
    import types
    mod = types.ModuleType("boto3")
    mod.client = boom
    monkeypatch.setattr(sa, "boto3", mod)
    stmts = statements_from(repo)
    machine = sa.machine_findings(stmts, {"s3", "iam", "sts"}, {})
    merged = sa.merge_findings(machine, None)
    assert merged == machine  # machine findings are the floor


# -------------------------------------------------------------- report + post --

def test_render_report_shape(repo):
    stmts = statements_from(repo)
    machine = sa.machine_findings(stmts, {"s3", "iam", "sts"}, {})
    report = sa.render_report(CFG, stmts, machine, None,
                              {"inputTokens": 5, "outputTokens": 6},
                              {"head_sha": "abc123def456"}, None)
    assert sa.MARKER in report
    assert "### Requested permissions" in report
    assert "### 🚨 Glaring concerns" in report
    assert "**HIGH**" in report
    assert "not an approval" in report
    assert "abc123def456" in report
    assert "5 in / 6 out" in report


def test_render_size_cap_note(repo):
    report = sa.render_report(CFG, statements_from(repo), [], None,
                              {"inputTokens": 0, "outputTokens": 0},
                              {"head_sha": "x"}, (3, 9))
    assert "3 of 9" in report


def test_sticky_comment_upsert(monkeypatch, tmp_path):
    event = {"pull_request": {"number": 7}}
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(event))
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    calls = []

    class Resp:
        def __init__(self, body):
            self.body = json.dumps(body).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    def urlopen(req, timeout=None):
        calls.append((req.method, req.full_url, req.data))
        if req.method == "GET":
            return Resp([{"id": 42, "body": "unrelated"},
                         {"id": 99, "body": sa.MARKER + " old"}])
        return Resp({})

    monkeypatch.setattr(sa.urllib.request, "urlopen", urlopen)
    assert sa.post_sticky(sa.MARKER + " v2") is True
    assert calls[0][0] == "GET"
    assert calls[1][0] == "PATCH" and "comments/99" in calls[1][1]
    assert "v2" in json.loads(calls[1][2])["body"]


def test_sticky_comment_posts_when_absent(monkeypatch, tmp_path):
    event = {"pull_request": {"number": 7}}
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(event))
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    calls = []

    class Resp:
        def __init__(self, body=b"null"):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    def urlopen(req, timeout=None):
        calls.append((req.method, req.full_url))
        return Resp(b"{}")

    monkeypatch.setattr(sa.urllib.request, "urlopen", urlopen)
    sa.post_sticky(sa.MARKER)
    assert calls[1][0] == "POST"


def test_sticky_comment_skipped_off_pr(monkeypatch, tmp_path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"action": "push"}))
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    assert sa.post_sticky(sa.MARKER) is False


# ------------------------------------------------------------------ end-to-end --

def test_main_end_to_end_advisory(monkeypatch, repo, tmp_path):
    fake_boto3(monkeypatch, json.dumps({"summary": "ok", "glaring": [], "findings": []}))
    diff = "diff --git a/tf/main.tf b/tf/main.tf\n--- a/tf/main.tf\n+++ b/tf/main.tf\n@@ +1 @@\n+new"
    out = tmp_path / "report.md"
    rc = sa.main([
        "--diff-file", str(_write(tmp_path, "d.diff", diff)),
        "--repo-root", str(repo),
        "--out", str(out),
        "--aws-region", "us-east-1",
        "--no-comment",
    ])
    assert rc == 0
    assert sa.MARKER in out.read_text()


def test_main_fail_on_high(monkeypatch, repo, tmp_path):
    fake_boto3(monkeypatch, json.dumps({"summary": "", "glaring": [], "findings": []}))
    diff = "diff --git a/tf/main.tf b/tf/main.tf\n--- a/tf/main.tf\n+++ b/tf/main.tf\n@@ +1 @@\n+new"
    out = tmp_path / "report.md"
    rc = sa.main([
        "--diff-file", str(_write(tmp_path, "d.diff", diff)),
        "--repo-root", str(repo),
        "--out", str(out),
        "--aws-region", "us-east-1",
        "--fail-on", "high",
        "--no-comment",
    ])
    assert rc == 1
    assert "**HIGH**" in out.read_text()


def test_main_no_relevant_changes_is_quiet(tmp_path):
    diff = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n+docs"
    rc = sa.main([
        "--diff-file", str(_write(tmp_path, "d.diff", diff)),
        "--repo-root", str(tmp_path),
        "--out", str(tmp_path / "r.md"),
        "--aws-region", "us-east-1",
        "--no-comment",
    ])
    assert rc == 0


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p
