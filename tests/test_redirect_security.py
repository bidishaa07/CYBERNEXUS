import socket
import pytest
from backend.app.engines.safe_http import UnsafeDestination, resolve_public_ips
from backend.app.services.scanner import _provider_state
import backend.app.engines.safe_http as safe_http

def _answers(*ips):
    return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0)) for ip in ips]

@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.1', '192.168.1.2', '169.254.1.1', '0.0.0.0', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1'])
def test_restricted_dns_answers_are_blocked(monkeypatch, ip):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: _answers(ip))
    with pytest.raises(UnsafeDestination):
        resolve_public_ips('controlled.test')

def test_public_ipv4_and_ipv6_are_returned(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: _answers('8.8.8.8', '2001:4860:4860::8888'))
    assert resolve_public_ips('controlled.test') == ['2001:4860:4860::8888', '8.8.8.8']

def test_mixed_public_and_private_answers_fail_closed(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: _answers('8.8.8.8', '10.0.0.1'))
    with pytest.raises(UnsafeDestination):
        resolve_public_ips('rebind.test')

def test_fetch_connects_to_validated_ip_not_hostname(monkeypatch):
    calls=[]
    monkeypatch.setattr(safe_http, 'resolve_public_ips', lambda hostname: ['8.8.8.8'])
    def fake_connect(address, timeout=None):
        calls.append(address)
        raise OSError('controlled test stop before network I/O')
    monkeypatch.setattr(socket, 'create_connection', fake_connect)
    with pytest.raises(OSError):
        safe_http.fetch('http://rebind.test/path')
    assert calls == [('8.8.8.8', 80)]

@pytest.mark.parametrize('status,state', [('not_configured','NOT_CONFIGURED'), ('configured','CONFIGURED'), ('connected','CONNECTED'), ('pending','PENDING'), ('completed','COMPLETED'), ('not_supported','NOT_SUPPORTED'), ('queried','NO_MATCH'), ('queried-threat','THREAT_DETECTED'), ('timeout','TIMEOUT'), ('unavailable','UNAVAILABLE'), ('invalid_credentials','INVALID_CREDENTIALS'), ('rate_limited','RATE_LIMITED'), ('provider_error','PROVIDER_ERROR')])
def test_provider_states_never_turn_failures_into_clean(status, state):
    item={'provider':'Test', 'status':status, 'verdict':'unknown'}
    if status == 'queried': item['verdict']='no_match'
    if status == 'queried-threat': item={'provider':'Test','status':'queried','verdict':'malicious'}
    assert _provider_state(item)['state'] == state
