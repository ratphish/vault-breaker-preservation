"""Wire contract controls: no game, DLL, process access, or network."""
import marathon_server as module
from marathon_protobuf import ProtobufReader


def times_from_reply(payload):
    top = {field: value for field, wire, value in ProtobufReader(payload).parse()}
    success = {field: value for field, wire, value in ProtobufReader(top[module.PB_TAG_SUCCESS]).parse()}
    return top[module.PB_TAG_SERVER_TIME], success[module.PB_SUB_EXPIRY]


def test_expiry_is_future_epoch_from_the_same_clock_sample(monkeypatch):
    monkeypatch.setattr(module, 'server_log', lambda message: None)
    samples = []
    def clock():
        samples.append(True)
        return 1_800_000_000.99 + 500 * (len(samples) - 1)
    monkeypatch.setattr(module.time, 'time', clock)
    status, payload = module.MarathonServer().handle_signon_request(b'ticket')
    now, expiry = times_from_reply(payload)
    assert status == 200
    assert now == 1_800_000_000
    assert expiry == now + 86400
    assert expiry > now
    assert len(samples) == 1


def test_reissued_reply_gets_fresh_absolute_expiry(monkeypatch):
    monkeypatch.setattr(module, 'server_log', lambda message: None)
    server = module.MarathonServer()
    monkeypatch.setattr(module.time, 'time', lambda: 1_800_000_000)
    _, first = server.handle_signon_request(b'first')
    monkeypatch.setattr(module.time, 'time', lambda: 1_800_086_401)
    _, second = server.handle_signon_request(b'second')
    first_now, first_expiry = times_from_reply(first)
    second_now, second_expiry = times_from_reply(second)
    assert first_expiry < second_now
    assert second_expiry == second_now + 86400
    assert first_now < second_now < second_expiry
