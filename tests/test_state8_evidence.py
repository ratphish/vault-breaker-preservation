"""Control-flow regression cases for the saved-capture auditor."""
from audit_state8_evidence import flow


def test_branch_target_after_ret_is_not_lost():
    # test edx,edx; jle +1; ret; mov rax,r9; ret
    report = flow(bytes.fromhex("85d27e01c34c89c8c3"), 0x1000, 0x1000, 0x2000)
    rows = {int(row['rva'], 16): row for row in report['instructions']}
    assert rows[0x1005]['instruction'] == 'mov rax, r9'
    assert rows[0x1008]['instruction'].startswith('ret')
    assert not report['runtime_observed']


def test_relative_call_outside_image_is_explicit():
    report = flow(bytes.fromhex("e8ffffff7fc3"), 0x1000, 0x1000, 0x2000)
    call = report['instructions'][0]
    assert call['call_target'] == '0x80001004'
    assert call['target_within_pe_image'] is False
    assert len(report['instructions']) == 2  # No invented callee bytes.
