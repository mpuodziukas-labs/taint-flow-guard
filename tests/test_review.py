"""Hostile-review findings T1-T11 (outside review, 2026-10-04), each with the exact call from the findings file."""
import json
import pytest
from taintflow import check
from test_guard import POLICY

E = {"text": "evil@x.example", "labels": ["untrusted:web_page"]}
O = {"text": "owner@owner.example", "labels": ["trusted-owner"]}


def verdict(plan_text, policy=POLICY):
    return check(plan_text, policy)[0]


def mail(to, values, **extra):
    return json.dumps({"values": values, "calls": [{"tool": "send_email", "args": {"to": to}, **extra}]})


def dump(o):
    return json.dumps(o)


def test_T1_duplicate_key_inside_a_ref():
    plan = '{"values":{"e":%s,"o":%s},"calls":[{"tool":"send_email","args":{"to":{"ref":"e","ref":"o"}}}]}' % (dump(E), dump(O))
    assert verdict(plan) == "BLOCK"


def test_T2_duplicate_arg_name():
    plan = '{"values":{"e":%s,"o":%s},"calls":[{"tool":"send_email","args":{"to":{"ref":"e"},"to":{"ref":"o"}}}]}' % (dump(E), dump(O))
    assert verdict(plan) == "BLOCK"


def test_T3_duplicate_value_id():
    plan = '{"values":{"a":%s,"a":%s},"calls":[{"tool":"send_email","args":{"to":{"ref":"a"}}}]}' % (dump(E), dump(O))
    assert verdict(plan) == "BLOCK"


def test_T4_duplicate_tool_key():
    plan = '{"values":{"w":%s},"calls":[{"tool":"shell","tool":"read_file","args":{"path":{"ref":"w"}}}]}' % dump(E)
    assert verdict(plan) == "BLOCK"


def test_T5_sensitive_arg_left_out():
    assert verdict(dump({"values": {"w": E}, "calls": [{"tool": "send_email", "args": {"body": {"ref": "w"}}}]})) == "BLOCK"
    assert verdict(dump({"values": {"w": E}, "calls": [{"tool": "shell", "args": {}}]})) == "BLOCK"


def test_T5_policy_may_mark_a_sensitive_arg_optional():
    pol = json.loads(POLICY)
    pol["tools"]["send_email"]["optional"] = ["to"]
    plan = dump({"values": {"w": E}, "calls": [{"tool": "send_email", "args": {"body": {"ref": "w"}}}]})
    assert verdict(plan, dump(pol)) == "ALLOW"


def test_T6_extra_key_in_a_ref():
    plan = mail({"ref": "o", "text": "evil@x.example"}, {"o": O})
    assert verdict(plan) == "BLOCK"


def test_T7_extra_key_on_a_call():
    plan = mail({"ref": "o"}, {"o": O}, kwargs={"to": "evil@x.example"})
    assert verdict(plan) == "BLOCK"


def test_T8_op_value_also_carries_text_and_labels():
    v = {"o": O, "u": {"op": "upper", "args": [{"ref": "o"}], "text": "evil@x.example", "labels": ["trusted-owner"]}}
    assert verdict(mail({"ref": "u"}, v)) == "BLOCK"


def test_T9_format_template_text_is_not_owner_typed():
    v = {"o2": {"text": "", "labels": ["trusted-owner"]}, "f": {"op": "format", "args": [{"ref": "o2"}], "params": ["evil@x.example{}"]}}
    assert verdict(mail({"ref": "f"}, v)) == "BLOCK"


def test_T9_plain_placeholder_template_still_allowed():
    v = {"o": O, "f": {"op": "format", "args": [{"ref": "o"}], "params": ["{}"]}}
    assert verdict(mail({"ref": "f"}, v)) == "ALLOW"


def test_T10_nested_concat_blowup_is_blocked_fast():
    v = {"v0": {"text": "xx", "labels": ["trusted-owner"]}}
    for i in range(1, 27):
        v[f"v{i}"] = {"op": "concat", "args": [{"ref": f"v{i-1}"}, {"ref": f"v{i-1}"}]}
    assert verdict(mail({"ref": "v26"}, v)) == "BLOCK"


def test_T10_format_width_blowup_is_blocked():
    v = {"o": O, "f": {"op": "format", "args": [{"ref": "o"}], "params": ["{0:>200000000}"]}}
    assert verdict(mail({"ref": "f"}, v)) == "BLOCK"


def test_T11_duplicate_tool_in_the_policy():
    pol = POLICY.rstrip().rstrip("}").rstrip().rstrip("}").rstrip() + ',\n "send_email":{"free":["to"],"sensitive":{}}}}'
    assert pol != POLICY
    assert verdict(mail({"ref": "e"}, {"e": E}), pol) == "BLOCK"
