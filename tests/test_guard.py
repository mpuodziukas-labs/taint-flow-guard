import json, pathlib, subprocess, sys
import pytest
from taintflow import check

FIX = pathlib.Path(__file__).parent / "fixtures"
ROOT = pathlib.Path(__file__).parent.parent
POLICY = (FIX / "policy.json").read_text()


def run(name, policy=POLICY):
    return check((FIX / f"{name}.json").read_text(), policy)


def only(findings):
    return [(f["call"], f["tool"], f["arg"], f["source"]) for f in findings]


PHRASES = ["exfil_classic_english", "exfil_paraphrase", "exfil_spanish", "exfil_german", "exfil_polite_cover_story"]


@pytest.mark.parametrize("name", PHRASES)
def test_injected_address_is_blocked_whatever_the_wording(name):
    verdict, found, _ = run(name)
    assert verdict == "BLOCK"
    assert only(found) == [(0, "send_email", "to", "untrusted:web_page")]


def test_all_five_wordings_get_the_identical_verdict_and_finding():
    outs = {json.dumps(run(n)[:2], sort_keys=True) for n in PHRASES}
    assert len(outs) == 1


def test_owner_typed_address_is_allowed():
    assert run("allow_owner_address")[:2] == ("ALLOW", [])


@pytest.mark.parametrize("name", ["block_launder_slice", "block_launder_upper", "block_launder_concat", "block_launder_format",
                                  "block_launder_json_dumps", "block_launder_json_loads", "block_launder_chain"])
def test_laundered_untrusted_value_is_still_blocked(name):
    verdict, found, _ = run(name)
    assert verdict == "BLOCK" and only(found) == [(0, "send_email", "to", "untrusted:web_page")]


def test_untrusted_text_in_a_free_arg_is_allowed_and_the_label_is_recorded():
    verdict, found, rec = run("allow_untrusted_body")
    assert (verdict, found) == ("ALLOW", [])
    assert {"call": 0, "tool": "send_email", "arg": "body", "labels": ["untrusted:web_page"]} in rec


def test_owner_may_pick_the_tool():
    assert run("allow_owner_chooses_tool")[0] == "ALLOW"


def test_untrusted_value_may_not_pick_the_tool():
    verdict, found, _ = run("block_untrusted_picks_tool")
    assert verdict == "BLOCK" and found[0]["source"] == "untrusted:web_page" and found[0]["call"] == 0


def test_untrusted_shell_argv_is_blocked():
    verdict, found, _ = run("block_shell_argv")
    assert verdict == "BLOCK" and only(found) == [(0, "shell", "argv", "untrusted:web_page")]


@pytest.mark.parametrize("name", ["block_raw_string_arg", "block_value_without_labels", "block_value_empty_labels", "block_invalid_label",
                                  "block_unknown_tool", "block_unknown_arg", "block_unknown_ref", "block_empty_plan"])
def test_unlabeled_or_unknown_is_blocked(name):
    verdict, found, _ = run(name)
    assert verdict == "BLOCK" and found, name


def test_unknown_tool_finding_names_the_call():
    assert only(run("block_unknown_tool")[1])[0][:2] == (0, "wire_money")


def test_unknown_arg_finding_names_the_arg():
    assert only(run("block_unknown_arg")[1])[0][:3] == (0, "send_email", "bcc")


def test_ask_owner_when_the_policy_says_ask():
    verdict, found, _ = run("ask_internal_kb_url")
    assert verdict == "ASK_OWNER" and only(found) == [(0, "http_get", "url", "untrusted:internal-kb")]


def test_block_outranks_ask():
    verdict, found, _ = run("block_kb_and_web_url")
    assert verdict == "BLOCK" and found[0]["source"] == "untrusted:web_page"


def test_an_ask_call_and_a_block_call_in_one_plan_is_block():
    verdict, found, _ = run("block_ask_then_block")
    assert verdict == "BLOCK" and [f["severity"] for f in found] == ["ASK_OWNER", "BLOCK"]


def test_a_blocked_second_call_blocks_the_plan_and_names_it():
    verdict, found, _ = run("block_after_allow")
    assert verdict == "BLOCK" and only(found) == [(1, "send_email", "to", "untrusted:web_page")]


@pytest.mark.parametrize("policy", ["{this is not json", "", "[]", '{"tools": []}', '{"tools": {"send_email": {}}}',
                                    '{"tools": {"send_email": {"sensitive": {"to": {"allow": "trusted-owner"}}, "free": []}}}'])
def test_policy_parse_or_shape_error_is_block(policy):
    verdict, found, _ = run("allow_owner_address", policy)
    assert verdict == "BLOCK" and found


@pytest.mark.parametrize("plan", ["[1, 2", "", "[]", '{"values": {}}', '{"values": [], "calls": []}', '{"values": {}, "calls": [1]}'])
def test_plan_parse_or_shape_error_is_block(plan):
    assert check(plan, POLICY)[0] == "BLOCK"


def test_the_guard_is_a_function_of_labels_not_text():
    p = json.loads((FIX / "exfil_classic_english.json").read_text())
    p["values"]["page"]["text"] = "completely different words, same origin " + p["values"]["page"]["text"][-30:]
    p["values"]["addr"]["params"] = [0, 5]
    assert check(json.dumps(p), POLICY)[0] == "BLOCK"


def cli(*args):
    return subprocess.run([sys.executable, "-m", "taintflow", *args], cwd=ROOT, capture_output=True, text=True, timeout=20)


def test_cli_exit_codes():
    f = lambda n: str(FIX / n)
    assert cli(f("policy.json"), f("allow_owner_address.json")).returncode == 0
    r = cli(f("policy.json"), f("exfil_german.json"))
    assert r.returncode == 1 and "BLOCK" in r.stdout and "send_email" in r.stdout and "untrusted:web_page" in r.stdout
    assert cli(f("policy.json"), f("ask_internal_kb_url.json")).returncode == 3
    assert cli(f("policy.json"), f("nonexistent.json")).returncode == 2
    assert cli(f("bad_policy.json"), f("allow_owner_address.json")).returncode == 1
    assert cli().returncode == 2
