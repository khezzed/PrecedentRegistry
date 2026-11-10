import hashlib
import json
import pytest

from conftest import (
    gl_mock,
    MockWebResponse,
    mock_web_responses,
    mock_llm_responses,
    mock_llm_dict,
    exec_prompt_call_history,
    ADDR_CREATOR,
    ADDR_AUTHOR_A,
    ADDR_AUTHOR_B,
    ADDR_AUTHOR_C,
    ADDR_OTHER,
    UserError,
    Address,
    u256,
)
from contracts.precedent_registry import (
    PrecedentRegistry,
    compute_effective_canon_context,
    cascade_retract_tree,
    compute_canon_digest,
    is_valid_evidence_url,
    parse_json_safely,
    _is_active,
    MAX_DOMAINS,
    MAX_TOTAL_ENTRIES_PER_DOMAIN,
    MAX_ACTIVE_ROOTS_PER_DOMAIN,
    MAX_CHILDREN_PER_ENTRY,
    MAX_DEPTH,
    MAX_ENTRIES_PER_ADDR,
    MAX_ATTEMPTS_PER_DOMAIN,
    MAX_TAG_LEN,
    MAX_SCOPE_LEN,
    MAX_STATEMENT_LEN,
    MAX_EVIDENCE_BYTES,
    MIN_EPOCH_DURATION,
    MAX_EPOCH_DURATION,
)

VALID_SHA = "0123456789abcdef0123456789abcdef01234567"
URL_ROOT_1 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/rfc/5xx-retry.txt"
URL_CHILD_2 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/rfc/503-no-retry.txt"
URL_ROOT_3 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/rfc/429-rate-limit.txt"
URL_ERRATA_1 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/errata/5xx-retract.txt"


def set_time(ts: int):
    gl_mock.message.timestamp = ts
    gl_mock.message_raw = {"datetime": ts}


def set_sender(addr: Address):
    gl_mock.message.sender_address = addr


# =============================================================================
# 1. Deterministic Helpers Unit Tests
# =============================================================================

def test_compute_effective_canon_context_root_and_child():
    entries = [
        {
            "id": 1,
            "scope_key": "root-scope",
            "rule_statement": "Root rule statement",
            "evidence_digest": "sha1",
            "parent_id": 0,
            "status": "ACTIVE_CARVED",
            "children": [2],
        },
        {
            "id": 2,
            "scope_key": "child-scope",
            "rule_statement": "Child carve-out statement",
            "evidence_digest": "sha2",
            "parent_id": 1,
            "status": "ACTIVE",
            "children": [],
        },
        {
            "id": 3,
            "scope_key": "retracted-scope",
            "rule_statement": "Old rule",
            "evidence_digest": "sha3",
            "parent_id": 0,
            "status": "RETRACTED",
            "children": [],
        },
    ]

    # For root proposal (target_parent_id == 0): returns all active entries
    root_context = compute_effective_canon_context(entries, 0)
    assert len(root_context) == 2
    assert root_context[0]["id"] == 1
    assert root_context[0]["children"] == [2]
    assert root_context[1]["id"] == 2
    assert root_context[1]["children"] == []

    # For child proposal targeting Entry 1: returns [parent] + active siblings
    child_context = compute_effective_canon_context(entries, 1)
    assert len(child_context) == 2
    assert child_context[0]["id"] == 1
    assert child_context[1]["id"] == 2

    # Targeting non-active or missing parent returns empty list
    missing_context = compute_effective_canon_context(entries, 999)
    assert missing_context == []

    retracted_context = compute_effective_canon_context(entries, 3)
    assert retracted_context == []


def test_cascade_retract_tree_multi_level():
    """
    Multi-level cascade: Entry 1 (depth 1) -> Entry 2 (depth 2) -> Entry 3 (depth 3).
    Retracting Entry 1 orphans both Entry 2 and Entry 3.
    """
    entries = [
        {
            "id": 1,
            "parent_id": 0,
            "status": "ACTIVE_CARVED",
            "children": [2],
        },
        {
            "id": 2,
            "parent_id": 1,
            "status": "ACTIVE_CARVED",
            "children": [3],
        },
        {
            "id": 3,
            "parent_id": 2,
            "status": "ACTIVE",
            "children": [],
        },
        {
            "id": 4,
            "parent_id": 0,
            "status": "ACTIVE",
            "children": [],
        },
    ]

    orphaned = cascade_retract_tree(entries, 1)
    assert sorted(orphaned) == [2, 3]
    assert entries[0]["status"] == "RETRACTED"
    assert entries[1]["status"] == "ORPHANED_BY_PARENT"
    assert entries[2]["status"] == "ORPHANED_BY_PARENT"
    # Sibling / unrelated root 4 remains active
    assert entries[3]["status"] == "ACTIVE"


def test_cascade_retract_tree_sibling_survival_and_parent_revert():
    """
    Parent Entry 1 has two active children (Entry 2 and Entry 3).
    1) Retracting Entry 2 leaves Entry 3 ACTIVE and Entry 1 ACTIVE_CARVED.
    2) Retracting Entry 3 leaves Entry 1 with 0 active children, so Entry 1 reverts to ACTIVE.
    """
    entries = [
        {
            "id": 1,
            "parent_id": 0,
            "status": "ACTIVE_CARVED",
            "children": [2, 3],
        },
        {
            "id": 2,
            "parent_id": 1,
            "status": "ACTIVE",
            "children": [],
        },
        {
            "id": 3,
            "parent_id": 1,
            "status": "ACTIVE",
            "children": [],
        },
    ]

    # Retract child 2
    orphaned_2 = cascade_retract_tree(entries, 2)
    assert orphaned_2 == []
    assert entries[1]["status"] == "RETRACTED"
    # Sibling 3 survives intact
    assert entries[2]["status"] == "ACTIVE"
    # Parent 1 still has active child 3, so status remains ACTIVE_CARVED
    assert entries[0]["status"] == "ACTIVE_CARVED"
    assert entries[0]["children"] == [3]

    # Now retract child 3 (sole remaining child)
    orphaned_3 = cascade_retract_tree(entries, 3)
    assert orphaned_3 == []
    assert entries[2]["status"] == "RETRACTED"
    # Parent 1 now has 0 active children -> reverts to ACTIVE
    assert entries[0]["status"] == "ACTIVE"
    assert entries[0]["children"] == []


def test_compute_canon_digest():
    empty_digest = compute_canon_digest([])
    expected_empty = hashlib.sha256(b"[]").hexdigest()
    assert empty_digest == expected_empty

    entries = [
        {
            "id": 1,
            "scope_key": "scope-a",
            "rule_statement": "statement a",
            "evidence_digest": "dig-a",
            "parent_id": 0,
            "status": "ACTIVE",
            "children": [],
        },
        {
            "id": 2,
            "scope_key": "scope-b",
            "rule_statement": "statement b",
            "evidence_digest": "dig-b",
            "parent_id": 0,
            "status": "RETRACTED",
            "children": [],
        },
    ]

    digest = compute_canon_digest(entries)
    # Only entry 1 should be included
    item = {
        "id": 1,
        "scope_key": "scope-a",
        "rule_statement": "statement a",
        "evidence_digest": "dig-a",
        "parent_id": 0,
        "status": "ACTIVE",
        "children": [],
    }
    expected = hashlib.sha256(json.dumps([item], sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert digest == expected


def test_is_valid_evidence_url():
    valid = f"https://raw.githubusercontent.com/owner/repo/{VALID_SHA}/path/to/spec.txt"
    assert is_valid_evidence_url(valid) is True

    # Bad conditions
    assert is_valid_evidence_url(None) is False
    assert is_valid_evidence_url("http://raw.githubusercontent.com/owner/repo/0123/a.txt") is False
    assert is_valid_evidence_url(valid + "?query=1") is False
    assert is_valid_evidence_url(valid + "#frag") is False
    assert is_valid_evidence_url(f"https://raw.githubusercontent.com/owner/repo/{VALID_SHA}/../spec.txt") is False
    assert is_valid_evidence_url(f"https://raw.githubusercontent.com/owner/repo/main/spec.txt") is False
    assert is_valid_evidence_url(f"https://raw.githubusercontent.com/owner/repo/{VALID_SHA}//spec.txt") is False


def test_parse_json_safely():
    assert parse_json_safely({"test": 1}) == {"test": 1}
    assert parse_json_safely('{"test": 2}') == {"test": 2}
    assert parse_json_safely('```json\n{"test": 3}\n```') == {"test": 3}
    assert parse_json_safely('prefix {"test": 4} suffix') == {"test": 4}
    assert parse_json_safely('invalid json') == {}
    assert parse_json_safely(12345) == {}


# =============================================================================
# 2. End-to-End Path-Dependent Canon Evolution
# =============================================================================

def test_e2e_path_dependent_canon_evolution():
    """
    Full story:
    1. Open domain 'http-retry'.
    2. Admit Root Entry 1 ('5xx-retry', INITIAL, ACTIVE).
    3. Contradicting rule ('503-no-retry') as root (target_parent_id=0) is REJECTED (CONTRADICTS).
    4. Same '503-no-retry' as carve-out (target_parent_id=1) is ADMITTED as Entry 2 (NARROWS).
       Entry 1 becomes ACTIVE_CARVED with children=[2].
    5. Admit orthogonal Root Entry 3 ('429-rate-limit', ORTHOGONAL).
    6. Retract Entry 1 with errata -> Entry 1 RETRACTED, Entry 2 ORPHANED_BY_PARENT, Entry 3 remains ACTIVE!
    7. Submitting a new root rule on '503' now succeeds as ORTHOGONAL.
    """
    registry = PrecedentRegistry()
    set_time(1700000000)
    set_sender(ADDR_CREATOR)

    # 1. Open domain
    res_open = registry.open_domain("http-retry", 86400)
    assert res_open == "OPENED:http-retry"
    assert registry.get_domain_count() == 1

    # Setup web evidence
    body_5xx = b"RFC-spec: All HTTP 5xx responses must be retried up to 3 times with exponential backoff."
    body_503 = b"RFC-spec-503: HTTP 503 Service Unavailable must NOT be retried."
    body_429 = b"RFC-spec-429: HTTP 429 Too Many Requests must wait for Retry-After header."
    body_errata = b"RFC-Errata: HTTP 5xx retry specification is hereby fully deprecated and retracted."

    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=body_5xx)
    mock_web_responses[URL_CHILD_2] = MockWebResponse(status=200, body=body_503)
    mock_web_responses[URL_ROOT_3] = MockWebResponse(status=200, body=body_429)
    mock_web_responses[URL_ERRATA_1] = MockWebResponse(status=200, body=body_errata)

    # 2. Admit Root Entry 1 (first rule -> relation is INITIAL without prompt 2)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    set_sender(ADDR_AUTHOR_A)

    res_entry1 = registry.propose_entry(
        "http-retry",
        "5xx-responses",
        "All HTTP 5xx responses must be retried up to 3 times with exponential backoff.",
        URL_ROOT_1,
        0,
    )
    assert res_entry1 == "ADMITTED:ENTRY_1:RELATION_INITIAL"

    entry1_data = json.loads(registry.get_entry(1))
    assert entry1_data["status"] == "ACTIVE"
    assert entry1_data["depth"] == 1
    assert entry1_data["children"] == []

    # 3. Attempt contradicting rule as a root -> LLM judges CONTRADICTS -> rejected
    def llm_contradict(prompt: str) -> str:
        if "supports a proposed technical rule" in prompt:
            return json.dumps({"premise": "SUPPORTED"})
        if "relates to the existing active canon" in prompt:
            return json.dumps({"relation": "CONTRADICTS"})
        return json.dumps({})

    mock_llm_responses.append(llm_contradict)

    set_sender(ADDR_AUTHOR_B)
    res_reject = registry.propose_entry(
        "http-retry",
        "503-responses",
        "HTTP 503 responses must NOT be retried.",
        URL_CHILD_2,
        0,
    )
    assert res_reject == "REJECTED:FETCH_OK:PREMISE_SUPPORTED:RELATION_CONTRADICTS"
    assert registry.get_entry_count() == 1

    # 4. Submit same 503 rule as narrowing carve-out to Entry 1 -> LLM judges NARROWS -> admitted
    mock_llm_responses.clear()

    def llm_narrows(prompt: str) -> str:
        if "supports a proposed technical rule" in prompt:
            return json.dumps({"premise": "SUPPORTED"})
        if "is a valid narrowing exception" in prompt:
            return json.dumps({"relation": "NARROWS"})
        return json.dumps({})

    mock_llm_responses.append(llm_narrows)

    res_entry2 = registry.propose_entry(
        "http-retry",
        "503-responses",
        "HTTP 503 responses must NOT be retried.",
        URL_CHILD_2,
        1,
    )
    assert res_entry2 == "ADMITTED:ENTRY_2:RELATION_NARROWS"

    entry2_data = json.loads(registry.get_entry(2))
    assert entry2_data["status"] == "ACTIVE"
    assert entry2_data["depth"] == 2
    assert entry2_data["parent_id"] == 1

    entry1_updated = json.loads(registry.get_entry(1))
    assert entry1_updated["status"] == "ACTIVE_CARVED"
    assert entry1_updated["children"] == [2]

    # 5. Admit orthogonal Root Entry 3 ('429-rate-limit')
    mock_llm_responses.clear()

    def llm_orthogonal(prompt: str) -> str:
        if "supports a proposed technical rule" in prompt:
            return json.dumps({"premise": "SUPPORTED"})
        if "relates to the existing active canon" in prompt:
            return json.dumps({"relation": "ORTHOGONAL"})
        return json.dumps({})

    mock_llm_responses.append(llm_orthogonal)

    set_sender(ADDR_AUTHOR_C)
    res_entry3 = registry.propose_entry(
        "http-retry",
        "429-responses",
        "HTTP 429 Too Many Requests must wait for Retry-After header.",
        URL_ROOT_3,
        0,
    )
    assert res_entry3 == "ADMITTED:ENTRY_3:RELATION_ORTHOGONAL"

    entry3_data = json.loads(registry.get_entry(3))
    assert entry3_data["status"] == "ACTIVE"
    assert entry3_data["depth"] == 1

    # 6. Retract Entry 1 with errata evidence
    mock_llm_responses.clear()
    mock_llm_dict["retracts a previously accepted technical rule"] = json.dumps({"verdict": "RETRACTED"})

    set_sender(ADDR_AUTHOR_A)  # Must be author of Entry 1
    res_retract = registry.retract_entry(1, URL_ERRATA_1)
    assert res_retract == "RETRACTED:ENTRY_1:ORPHANED_1"

    # Verify statuses: Entry 1 RETRACTED, Entry 2 ORPHANED_BY_PARENT, Entry 3 remains ACTIVE!
    e1 = json.loads(registry.get_entry(1))
    e2 = json.loads(registry.get_entry(2))
    e3 = json.loads(registry.get_entry(3))
    assert e1["status"] == "RETRACTED"
    assert e1["retraction_url"] == URL_ERRATA_1
    assert e1["retraction_digest"] == hashlib.sha256(body_errata).hexdigest()
    assert e2["status"] == "ORPHANED_BY_PARENT"
    assert e3["status"] == "ACTIVE"
    assert e3["retraction_url"] == ""
    assert e3["retraction_digest"] == ""

    # Active canon only contains Entry 3 now
    active_canon = json.loads(registry.get_active_canon("http-retry"))
    assert len(active_canon) == 1
    assert active_canon[0]["id"] == 3

    # 7. Now that Entry 1 & 2 are gone, submitting a new root rule on 503 succeeds as ORTHOGONAL
    mock_llm_responses.clear()
    mock_llm_responses.append(llm_orthogonal)

    set_sender(ADDR_AUTHOR_B)
    URL_NEW_503 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/rfc/503-v2.txt"
    mock_web_responses[URL_NEW_503] = MockWebResponse(status=200, body=body_503)

    res_new_root = registry.propose_entry(
        "http-retry",
        "503-responses",
        "HTTP 503 responses must NOT be retried under new architecture.",
        URL_NEW_503,
        0,
    )
    assert res_new_root == "ADMITTED:ENTRY_4:RELATION_ORTHOGONAL"


# =============================================================================
# 3. Adversarial Leader Tests
# =============================================================================

def test_adversarial_forged_digest():
    """Leader attempts to forge evidence digest -> validator rejects."""
    registry = PrecedentRegistry()
    registry.open_domain("crypto-spec", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Valid cryptographic specification.")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})

    def forge_digest(leader_res):
        tampered = dict(leader_res)
        tampered["digest"] = "0" * 64
        return tampered

    gl_mock.adversarial_leader_fn = forge_digest

    with pytest.raises(UserError, match="CONSENSUS_VALIDATION_FAILED"):
        registry.propose_entry(
            "crypto-spec",
            "crypto",
            "Specification text",
            URL_ROOT_1,
            0,
        )


def test_adversarial_retraction_forged_digest():
    """Leader attempts to forge retraction errata digest -> validator rejects."""
    registry = PrecedentRegistry()
    registry.open_domain("retract-forge", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Original rule.")
    mock_web_responses[URL_ERRATA_1] = MockWebResponse(status=200, body=b"Errata text.")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["retracts a previously accepted technical rule"] = json.dumps({"verdict": "RETRACTED"})

    set_sender(ADDR_AUTHOR_A)
    registry.propose_entry("retract-forge", "scope", "Rule", URL_ROOT_1, 0)

    def forge_retract_digest(leader_res):
        tampered = dict(leader_res)
        tampered["digest"] = "f" * 64
        return tampered

    gl_mock.adversarial_leader_fn = forge_retract_digest

    with pytest.raises(UserError, match="CONSENSUS_VALIDATION_FAILED"):
        registry.retract_entry(1, URL_ERRATA_1)


def test_adversarial_forged_relation():
    """Leader attempts to forge relation from CONTRADICTS to ORTHOGONAL -> validator rejects."""
    registry = PrecedentRegistry()
    registry.open_domain("crypto-spec", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule 1")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})

    # First rule admitted
    registry.propose_entry("crypto-spec", "scope1", "Rule 1", URL_ROOT_1, 0)

    # Second rule evaluated: local validator would compute CONTRADICTS
    mock_llm_dict["relates to the existing active canon"] = json.dumps({"relation": "CONTRADICTS"})
    mock_web_responses[URL_CHILD_2] = MockWebResponse(status=200, body=b"Rule 2")

    def forge_relation(leader_res):
        tampered = dict(leader_res)
        tampered["relation"] = "ORTHOGONAL"
        return tampered

    gl_mock.adversarial_leader_fn = forge_relation

    with pytest.raises(UserError, match="CONSENSUS_VALIDATION_FAILED"):
        registry.propose_entry(
            "crypto-spec",
            "scope2",
            "Rule 2",
            URL_CHILD_2,
            0,
        )


def test_invented_llm_labels_normalized_to_unclear():
    """LLM hallucinating non-standard labels must have them normalized to UNCLEAR."""
    registry = PrecedentRegistry()
    registry.open_domain("norm-test", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule text")

    # Invented premise
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "TOTALLY_ACCURATE"})
    res = registry.propose_entry("norm-test", "scope", "Rule text", URL_ROOT_1, 0)
    assert res == "REJECTED:FETCH_OK:PREMISE_UNCLEAR:RELATION_UNCLEAR"

    # Invented root relation
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    # Need existing canon so Call 2 triggers
    # First admit a rule cleanly
    registry_clean = PrecedentRegistry()
    registry_clean.open_domain("norm-test-2", 86400)
    registry_clean.propose_entry("norm-test-2", "scope1", "Rule 1", URL_ROOT_1, 0)

    # Next proposal has invented relation
    mock_web_responses[URL_CHILD_2] = MockWebResponse(status=200, body=b"Rule 2")
    mock_llm_dict["relates to the existing active canon"] = json.dumps({"relation": "COMPATIBLE"})
    res2 = registry_clean.propose_entry("norm-test-2", "scope2", "Rule 2", URL_CHILD_2, 0)
    assert res2 == "REJECTED:FETCH_OK:PREMISE_SUPPORTED:RELATION_UNCLEAR"

    # Invented retraction verdict
    mock_llm_dict["retracts a previously accepted technical rule"] = json.dumps({"verdict": "DEPRECATED"})
    mock_web_responses[URL_ERRATA_1] = MockWebResponse(status=200, body=b"Errata text")
    res_retract = registry_clean.retract_entry(1, URL_ERRATA_1)
    assert res_retract == "REJECTED:FETCH_OK:VERDICT_UNCLEAR"


def test_unsupported_premise_skips_call_2():
    """When premise is UNSUPPORTED, Call 2 (relation prompt) is skipped and exec_prompt is called only once."""
    registry = PrecedentRegistry()
    registry.open_domain("skip-test", 86400)

    # Admit root 1 so domain has existing canon
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule 1")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    registry.propose_entry("skip-test", "scope1", "Rule 1", URL_ROOT_1, 0)

    # Reset call history
    exec_prompt_call_history.clear()

    # Rule 2 has UNSUPPORTED premise
    mock_web_responses[URL_CHILD_2] = MockWebResponse(status=200, body=b"Rule 2")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "UNSUPPORTED"})

    res = registry.propose_entry("skip-test", "scope2", "Rule 2", URL_CHILD_2, 0)
    assert res == "REJECTED:FETCH_OK:PREMISE_UNSUPPORTED:RELATION_UNCLEAR"
    # Exactly one prompt executed for leader (and one recomputed for validator in consensus = total 2 in mock)
    # The key is: no relation prompt was sent
    assert len(exec_prompt_call_history) == 2
    for call in exec_prompt_call_history:
        assert "judging whether evidence supports a proposed technical rule" in call
        assert "judging how a candidate root rule relates" not in call


# =============================================================================
# 4. Access Control, Replay & Lifecycle Guards
# =============================================================================

def test_unauthorized_retraction():
    """Non-author cannot retract an entry."""
    registry = PrecedentRegistry()
    registry.open_domain("auth-test", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule 1")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})

    set_sender(ADDR_AUTHOR_A)
    registry.propose_entry("auth-test", "scope", "Rule", URL_ROOT_1, 0)

    # Attempt retract as ADDR_AUTHOR_B
    set_sender(ADDR_AUTHOR_B)
    with pytest.raises(UserError, match="UNAUTHORIZED_RETRACTION"):
        registry.retract_entry(1, URL_ERRATA_1)


def test_replay_proposal():
    """Duplicate proposal replay must raise REPLAY_SUBMISSION."""
    registry = PrecedentRegistry()
    registry.open_domain("replay-test", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule 1")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})

    registry.propose_entry("replay-test", "scope", "Rule", URL_ROOT_1, 0)

    with pytest.raises(UserError, match="REPLAY_SUBMISSION"):
        registry.propose_entry("replay-test", "scope", "Rule", URL_ROOT_1, 0)


def test_replay_retraction():
    """Duplicate retraction attempt must raise REPLAY_RETRACTION."""
    registry = PrecedentRegistry()
    registry.open_domain("replay-retract", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule 1")
    mock_web_responses[URL_ERRATA_1] = MockWebResponse(status=200, body=b"Errata")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["retracts a previously accepted technical rule"] = json.dumps({"verdict": "NOT_RETRACTED"})

    set_sender(ADDR_AUTHOR_A)
    registry.propose_entry("replay-retract", "scope", "Rule", URL_ROOT_1, 0)

    # First retraction attempt fails verdict -> saved attempts & replay key
    res1 = registry.retract_entry(1, URL_ERRATA_1)
    assert res1 == "REJECTED:FETCH_OK:VERDICT_NOT_RETRACTED"

    # Second retraction attempt with same URL raises REPLAY_RETRACTION
    with pytest.raises(UserError, match="REPLAY_RETRACTION"):
        registry.retract_entry(1, URL_ERRATA_1)


def test_parent_not_active_guards():
    """Targeting non-existent, retracted, or orphaned parent raises PARENT_NOT_ACTIVE."""
    registry = PrecedentRegistry()
    registry.open_domain("parent-test", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Rule 1")
    mock_web_responses[URL_CHILD_2] = MockWebResponse(status=200, body=b"Rule 2")
    mock_web_responses[URL_ERRATA_1] = MockWebResponse(status=200, body=b"Errata")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["is a valid narrowing exception"] = json.dumps({"relation": "NARROWS"})
    mock_llm_dict["retracts a previously accepted technical rule"] = json.dumps({"verdict": "RETRACTED"})

    # Non-existent parent
    with pytest.raises(UserError, match="PARENT_NOT_ACTIVE"):
        registry.propose_entry("parent-test", "scope", "Rule", URL_ROOT_1, 999)

    # Admit Root 1 and Child 2
    set_sender(ADDR_AUTHOR_A)
    registry.propose_entry("parent-test", "scope1", "Rule 1", URL_ROOT_1, 0)
    registry.propose_entry("parent-test", "scope2", "Rule 2", URL_CHILD_2, 1)

    # Retract Root 1 -> Root 1 becomes RETRACTED, Child 2 becomes ORPHANED_BY_PARENT
    registry.retract_entry(1, URL_ERRATA_1)

    URL_TEST = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/rfc/test.txt"
    mock_web_responses[URL_TEST] = MockWebResponse(status=200, body=b"Test rule")

    # Targeting retracted root 1 raises PARENT_NOT_ACTIVE
    with pytest.raises(UserError, match="PARENT_NOT_ACTIVE"):
        registry.propose_entry("parent-test", "sub", "Sub-rule", URL_TEST, 1)

    # Targeting orphaned child 2 raises PARENT_NOT_ACTIVE
    with pytest.raises(UserError, match="PARENT_NOT_ACTIVE"):
        registry.propose_entry("parent-test", "sub", "Sub-rule", URL_TEST, 2)


def test_max_depth_exceeded():
    """Depth > 3 raises MAX_DEPTH_EXCEEDED."""
    registry = PrecedentRegistry()
    registry.open_domain("depth-test", 86400)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["is a valid narrowing exception"] = json.dumps({"relation": "NARROWS"})

    url_depth1 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/d1.txt"
    url_depth2 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/d2.txt"
    url_depth3 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/d3.txt"
    url_depth4 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/d4.txt"

    mock_web_responses[url_depth1] = MockWebResponse(status=200, body=b"D1")
    mock_web_responses[url_depth2] = MockWebResponse(status=200, body=b"D2")
    mock_web_responses[url_depth3] = MockWebResponse(status=200, body=b"D3")
    mock_web_responses[url_depth4] = MockWebResponse(status=200, body=b"D4")

    # Entry 1 (depth 1)
    registry.propose_entry("depth-test", "d1", "Depth 1", url_depth1, 0)
    # Entry 2 (depth 2)
    registry.propose_entry("depth-test", "d2", "Depth 2", url_depth2, 1)
    # Entry 3 (depth 3)
    registry.propose_entry("depth-test", "d3", "Depth 3", url_depth3, 2)

    # Entry 4 targeting Entry 3 (depth 3) would have depth 4 -> blocked!
    with pytest.raises(UserError, match="MAX_DEPTH_EXCEEDED"):
        registry.propose_entry("depth-test", "d4", "Depth 4", url_depth4, 3)


def test_max_children_exceeded():
    """More than MAX_CHILDREN_PER_ENTRY (4) active children raises MAX_CHILDREN_EXCEEDED."""
    registry = PrecedentRegistry()
    registry.open_domain("children-test", 86400)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["is a valid narrowing exception"] = json.dumps({"relation": "NARROWS"})

    url_root = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/root.txt"
    mock_web_responses[url_root] = MockWebResponse(status=200, body=b"Root")
    registry.propose_entry("children-test", "root", "Root", url_root, 0)

    for i in range(1, 5):
        url_child = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/c{i}.txt"
        mock_web_responses[url_child] = MockWebResponse(status=200, body=f"Child {i}".encode())
        registry.propose_entry("children-test", f"c{i}", f"Child {i}", url_child, 1)

    # 5th child targeting Entry 1
    url_5 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/c5.txt"
    mock_web_responses[url_5] = MockWebResponse(status=200, body=b"Child 5")
    with pytest.raises(UserError, match="MAX_CHILDREN_EXCEEDED"):
        registry.propose_entry("children-test", "c5", "Child 5", url_5, 1)


def test_max_attempts_exceeded():
    """Attempts exceeding MAX_ATTEMPTS_PER_DOMAIN (48) raises MAX_ATTEMPTS_EXCEEDED."""
    registry = PrecedentRegistry()
    registry.open_domain("attempt-test", 86400)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "UNSUPPORTED"})

    for i in range(48):
        url = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/att{i}.txt"
        mock_web_responses[url] = MockWebResponse(status=200, body=f"Att {i}".encode())
        res = registry.propose_entry("attempt-test", f"scope{i}", f"Statement {i}", url, 0)
        assert "REJECTED" in res

    # 49th attempt
    url_49 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/att49.txt"
    mock_web_responses[url_49] = MockWebResponse(status=200, body=b"Att 49")
    with pytest.raises(UserError, match="MAX_ATTEMPTS_EXCEEDED"):
        registry.propose_entry("attempt-test", "scope49", "Statement 49", url_49, 0)


def test_max_entries_per_addr():
    """An author cannot exceed MAX_ENTRIES_PER_ADDR (6) active entries."""
    registry = PrecedentRegistry()
    registry.open_domain("addr-test", 86400)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["relates to the existing active canon"] = json.dumps({"relation": "ORTHOGONAL"})

    set_sender(ADDR_AUTHOR_A)
    for i in range(6):
        url = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/addr{i}.txt"
        mock_web_responses[url] = MockWebResponse(status=200, body=f"Rule {i}".encode())
        registry.propose_entry("addr-test", f"scope{i}", f"Rule {i}", url, 0)

    # 7th active entry by same author
    url_7 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/addr7.txt"
    mock_web_responses[url_7] = MockWebResponse(status=200, body=b"Rule 7")
    with pytest.raises(UserError, match="MAX_ENTRIES_PER_ADDR_EXCEEDED"):
        registry.propose_entry("addr-test", "scope7", "Rule 7", url_7, 0)


def test_max_active_roots_per_domain():
    """Cannot exceed MAX_ACTIVE_ROOTS_PER_DOMAIN (8)."""
    registry = PrecedentRegistry()
    registry.open_domain("roots-test", 86400)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})
    mock_llm_dict["relates to the existing active canon"] = json.dumps({"relation": "ORTHOGONAL"})

    # Use multiple authors to not trip MAX_ENTRIES_PER_ADDR
    authors = [
        Address(f"0x{str(i) * 40}") for i in range(1, 9)
    ]
    for i, auth in enumerate(authors):
        set_sender(auth)
        url = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/root{i}.txt"
        mock_web_responses[url] = MockWebResponse(status=200, body=f"Root {i}".encode())
        registry.propose_entry("roots-test", f"scope{i}", f"Root {i}", url, 0)

    # 9th root
    set_sender(ADDR_OTHER)
    url_9 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/root9.txt"
    mock_web_responses[url_9] = MockWebResponse(status=200, body=b"Root 9")
    with pytest.raises(UserError, match="MAX_ACTIVE_ROOTS_EXCEEDED"):
        registry.propose_entry("roots-test", "scope9", "Root 9", url_9, 0)


def test_max_total_entries_exceeded():
    """Total entries stored in a domain cannot exceed MAX_TOTAL_ENTRIES_PER_DOMAIN (24)."""
    registry = PrecedentRegistry()
    registry.open_domain("total-test", 86400)

    domain_raw = registry.domains.get("total-test")
    domain = json.loads(domain_raw)
    domain["entries"] = [
        {
            "id": i,
            "author": str(ADDR_AUTHOR_A),
            "scope_key": f"scope{i}",
            "rule_statement": f"Rule {i}",
            "evidence_url": URL_ROOT_1,
            "evidence_digest": "digest",
            "retraction_url": "",
            "retraction_digest": "",
            "parent_id": 0,
            "depth": 1,
            "children": [],
            "status": "RETRACTED",
            "relation": "INITIAL",
        }
        for i in range(1, MAX_TOTAL_ENTRIES_PER_DOMAIN + 1)
    ]
    registry.domains["total-test"] = json.dumps(domain)

    with pytest.raises(UserError, match="MAX_TOTAL_ENTRIES_EXCEEDED"):
        registry.propose_entry("total-test", "scope25", "Rule 25", URL_ROOT_1, 0)


def test_domain_lifecycle_and_freeze():
    """
    Freeze lifecycle:
    - Premature freeze raises EPOCH_NOT_READY.
    - Double freeze raises DOMAIN_ALREADY_FROZEN.
    - Proposal on frozen domain or after deadline raises error.
    """
    registry = PrecedentRegistry()
    set_time(1700000000)
    registry.open_domain("freeze-test", 3600)  # Deadline 1700003600

    # Premature freeze
    with pytest.raises(UserError, match="EPOCH_NOT_READY"):
        registry.freeze_epoch("freeze-test")

    # Fast-forward past deadline
    set_time(1700003600)
    res_freeze = registry.freeze_epoch("freeze-test")
    assert res_freeze.startswith("FROZEN:EPOCH_1:DIGEST_")

    # Double freeze
    with pytest.raises(UserError, match="DOMAIN_ALREADY_FROZEN"):
        registry.freeze_epoch("freeze-test")

    # Proposal on frozen domain
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Spec")
    with pytest.raises(UserError, match="DOMAIN_NOT_OPEN"):
        registry.propose_entry("freeze-test", "scope", "Rule", URL_ROOT_1, 0)


def test_epoch_expired_on_open_domain():
    """Proposal when now >= epoch_deadline on open domain raises EPOCH_EXPIRED."""
    registry = PrecedentRegistry()
    set_time(1700000000)
    registry.open_domain("expire-test", 100)  # Deadline 1700000100

    set_time(1700000101)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Spec")
    with pytest.raises(UserError, match="EPOCH_EXPIRED"):
        registry.propose_entry("expire-test", "scope", "Rule", URL_ROOT_1, 0)


def test_domain_tag_and_duration_guards():
    """Domain creation input validations."""
    registry = PrecedentRegistry()
    set_time(1700000000)

    # Invalid tag characters
    with pytest.raises(UserError, match="INVALID_DOMAIN_TAG"):
        registry.open_domain("Invalid_Tag!", 3600)

    # Empty tag
    with pytest.raises(UserError, match="INVALID_DOMAIN_TAG"):
        registry.open_domain("", 3600)

    # Tag too long (> 32)
    with pytest.raises(UserError, match="INVALID_DOMAIN_TAG"):
        registry.open_domain("a" * 33, 3600)

    # Duplicate domain
    registry.open_domain("dup-tag", 3600)
    with pytest.raises(UserError, match="DOMAIN_ALREADY_EXISTS"):
        registry.open_domain("dup-tag", 3600)

    # Invalid epoch duration (< 60 or > 30 days)
    with pytest.raises(UserError, match="INVALID_EPOCH_DURATION"):
        registry.open_domain("short-epoch", 59)
    with pytest.raises(UserError, match="INVALID_EPOCH_DURATION"):
        registry.open_domain("long-epoch", 30 * 86400 + 1)

    # Max domains bound (8)
    for i in range(1, 8):
        registry.open_domain(f"dom-{i}", 3600)
    with pytest.raises(UserError, match="MAX_DOMAINS_EXCEEDED"):
        registry.open_domain("dom-overflow", 3600)


def test_proposal_text_length_guards():
    registry = PrecedentRegistry()
    registry.open_domain("length-test", 86400)

    # Scope too long
    with pytest.raises(UserError, match="INVALID_SCOPE_LENGTH"):
        registry.propose_entry("length-test", "x" * 81, "Rule", URL_ROOT_1, 0)

    # Rule statement too long
    with pytest.raises(UserError, match="INVALID_STATEMENT_LENGTH"):
        registry.propose_entry("length-test", "scope", "x" * 281, URL_ROOT_1, 0)


def test_no_block_time_guard():
    """Missing block time raises NO_BLOCK_TIME."""
    registry = PrecedentRegistry()
    gl_mock.message_raw = None
    gl_mock.message.timestamp = None

    with pytest.raises(UserError, match="NO_BLOCK_TIME"):
        registry.open_domain("no-time", 3600)


# =============================================================================
# 5. Evidence Failures
# =============================================================================

def test_evidence_fetch_failures():
    """Evidence fetch edge cases."""
    registry = PrecedentRegistry()
    registry.open_domain("fetch-test", 86400)
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})

    # HTTP 500
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=500, body=b"Error")
    res500 = registry.propose_entry("fetch-test", "scope", "Rule 1", URL_ROOT_1, 0)
    assert res500 == "REJECTED:FETCH_HTTP_500:PREMISE_UNCLEAR:RELATION_UNCLEAR"

    # Empty body
    mock_web_responses[URL_CHILD_2] = MockWebResponse(status=200, body=b"")
    res_empty = registry.propose_entry("fetch-test", "scope", "Rule 2", URL_CHILD_2, 0)
    assert res_empty == "REJECTED:FETCH_EMPTY:PREMISE_UNCLEAR:RELATION_UNCLEAR"

    # Oversized body (> 8000 bytes)
    mock_web_responses[URL_ROOT_3] = MockWebResponse(status=200, body=b"A" * 8001)
    res_over = registry.propose_entry("fetch-test", "scope", "Rule 3", URL_ROOT_3, 0)
    assert res_over == "REJECTED:FETCH_OVERSIZED:PREMISE_UNCLEAR:RELATION_UNCLEAR"

    # Bad UTF-8
    URL_BAD_UTF8 = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/bad-utf8.txt"
    mock_web_responses[URL_BAD_UTF8] = MockWebResponse(status=200, body=b"\xff\xfe\xfd")
    res_utf8 = registry.propose_entry("fetch-test", "scope", "Rule 4", URL_BAD_UTF8, 0)
    assert res_utf8 == "REJECTED:FETCH_BAD_UTF8:PREMISE_UNCLEAR:RELATION_UNCLEAR"

    # Network fetch exception
    URL_EXC = f"https://raw.githubusercontent.com/test-org/specs/{VALID_SHA}/exc.txt"
    mock_web_responses[URL_EXC] = RuntimeError("Connection dropped")
    res_exc = registry.propose_entry("fetch-test", "scope", "Rule 5", URL_EXC, 0)
    assert res_exc == "REJECTED:FETCH_FETCH_ERROR:PREMISE_UNCLEAR:RELATION_UNCLEAR"


def test_evidence_url_validation_rejections():
    """Unpinned branch URL, query string, fragment, .. path raise INVALID_EVIDENCE_URL before nondet."""
    registry = PrecedentRegistry()
    registry.open_domain("url-test", 86400)

    # Unpinned branch URL
    with pytest.raises(UserError, match="INVALID_EVIDENCE_URL"):
        registry.propose_entry(
            "url-test", "scope", "Rule",
            "https://raw.githubusercontent.com/owner/repo/main/spec.txt",
            0,
        )

    # Query string
    with pytest.raises(UserError, match="INVALID_EVIDENCE_URL"):
        registry.propose_entry(
            "url-test", "scope", "Rule",
            f"https://raw.githubusercontent.com/owner/repo/{VALID_SHA}/spec.txt?v=1",
            0,
        )

    # Fragment
    with pytest.raises(UserError, match="INVALID_EVIDENCE_URL"):
        registry.propose_entry(
            "url-test", "scope", "Rule",
            f"https://raw.githubusercontent.com/owner/repo/{VALID_SHA}/spec.txt#frag",
            0,
        )

    # .. path
    with pytest.raises(UserError, match="INVALID_EVIDENCE_URL"):
        registry.propose_entry(
            "url-test", "scope", "Rule",
            f"https://raw.githubusercontent.com/owner/repo/{VALID_SHA}/../spec.txt",
            0,
        )


# =============================================================================
# 6. Views and State Inspectors
# =============================================================================

def test_view_methods():
    registry = PrecedentRegistry()
    registry.open_domain("view-test", 86400)
    mock_web_responses[URL_ROOT_1] = MockWebResponse(status=200, body=b"Spec")
    mock_llm_dict["supports a proposed technical rule"] = json.dumps({"premise": "SUPPORTED"})

    registry.propose_entry("view-test", "scope-1", "Statement 1", URL_ROOT_1, 0)

    # get_domain
    domain_json = registry.get_domain("view-test")
    assert "view-test" in domain_json
    assert registry.get_domain("non-existent") == "{}"

    # get_entry
    entry_json = registry.get_entry(1)
    entry = json.loads(entry_json)
    assert entry["id"] == 1
    assert entry["scope_key"] == "scope-1"
    assert registry.get_entry(999) == "{}"

    # get_active_canon
    canon_json = registry.get_active_canon("view-test")
    canon = json.loads(canon_json)
    assert len(canon) == 1
    assert canon[0]["id"] == 1

    # get_domain_count and get_entry_count
    assert registry.get_domain_count() == 1
    assert registry.get_entry_count() == 1
