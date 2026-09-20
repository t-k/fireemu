"""Real TCP/worker tests: local synthetic servers, no production or Firebase SDK."""
from __future__ import annotations
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import pytest
import partition_cursor_wire as wire
from partition_cursor_collector import collect_local
from partition_cursor_offline_fixture import plan, Transport
from partition_cursor_shadow import loopback_transport

REQUEST={'method':'GET','path':'/v1/projects/demo-project/databases/(default)/documents/a/b','body':None}


@contextmanager
def server(response: bytes, *, delay=0, drip=False):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(.1)
    stop=threading.Event(); seen=[]
    def serve():
        try:
            while not stop.is_set():
                try:conn,_=listener.accept()
                except socket.timeout:continue
                except OSError:break
                with conn:
                    conn.settimeout(.3)
                    try:
                        data=b''
                        while b'\r\n\r\n' not in data:
                            part=conn.recv(4096)
                            if not part:break
                            data+=part
                        seen.append(data)
                        if delay:stop.wait(delay)
                        if drip:
                            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 50000\r\n\r\n{')
                            for _ in range(200):
                                if stop.wait(.03):break
                                conn.sendall(b' ')
                        else:conn.sendall(response)
                    except (OSError,TimeoutError):pass
        finally:listener.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:yield f'http://127.0.0.1:{listener.getsockname()[1]}',seen
    finally:
        stop.set();thread.join(timeout=2);assert not thread.is_alive()


def message(raw=b'{}',*,status=200,extra=b'',media=b'application/json',length=None):
    return (f'HTTP/1.1 {status} response\r\n'.encode()+b'Content-Type: '+media+b'\r\n'
            +f'Content-Length: {len(raw) if length is None else length}\r\n'.encode()+extra+b'Connection: close\r\n\r\n'+raw)


@pytest.mark.parametrize('origin', ['http://localhost:8080','http://127.0.0.1','http://[::1]',
 'http://user@127.0.0.1:8080','http://127.0.0.1:8080?x','http://127.0.0.1:8080#x',
 'http://127.0.0.1:bad','http://127.0.0.1:0','http://127.0.0.1:65536','https://127.0.0.1:8080',
 'http://127.0.0.1:8080/subpath','http://127.0.0.1:8080?','http://127.0.0.1:8080#',
 'http://127.0.0.1:8080\n','http://[::1]:0',None])
def test_origin_refused_before_files_or_transport(tmp_path,origin):
    transport=Transport(plan())
    with pytest.raises(PermissionError):collect_local(plan(),transport,tmp_path/'out',origin=origin)
    assert not (tmp_path/'out').exists();assert not transport.sent


@pytest.mark.parametrize('raw,status', [(b'{}',200),(b'[]',200),
 (b'[{"readTime":"2026-09-20T00:00:00Z"}]',200),
 ('{"message":"日本語"}'.encode(),200),
 (b'{"error":{"code":404,"status":"NOT_FOUND"}}',404),
 (b'{"error":{"code":400,"status":"INVALID_ARGUMENT"}}',400)])
def test_fixed_worker_preserves_exact_response_bytes_and_status(raw,status):
    with server(message(raw,status=status)) as (origin,seen):
        result=wire.request(origin,REQUEST,timeout=2)
    assert result['rawBody']==raw and result['body']==json.loads(raw)
    assert result['status']==status and result['complete'] is True
    assert result['byteCount']==len(raw);assert len(seen)==1
    assert b'Authorization: Bearer owner' in seen[0]


@pytest.mark.parametrize('raw', [b'{}',b'[]'])
def test_trailing_slash_origin_does_not_double_the_request_path(raw):
    with server(message(raw)) as (origin,seen):result=loopback_transport(origin+'/')(REQUEST)
    assert result['rawBody']==raw
    assert seen[0].startswith(b'GET /v1/')


@pytest.mark.parametrize('response', [
 message(b'{"a":1,"a":2}'),message(b'{"v":NaN}'),message(b'{"v":1e999}'),
 message(b'{}',media=b'text/html'),message(b'{}',extra=b'Content-Type: application/json\r\n'),
 message(b'{}',extra=b'Content-Length: 2\r\n'),message(b'{}',length=999),
 message(b'[]',extra=b'Transfer-Encoding: chunked\r\n'),message(b'x'*65537),
 message(b'{}',extra=b'Content-Length: nope\r\n'),message('{}'.encode('utf-16')),
 message(b''),message(b'null'),message(b'123'),message(b'{"a":'),
])
def test_invalid_transport_or_json_never_becomes_typed_evidence(response):
    with server(response) as (origin,seen):
        with pytest.raises(ValueError,match='unusable'):wire.request(origin,REQUEST,timeout=2)
    assert len(seen)==1


def test_redirect_is_not_followed_even_to_a_second_loopback_server():
    with server(message(b'{}')) as (target,target_seen):
        redirect=message(b'',status=302,extra=f'Location: {target}/stolen\r\n'.encode())
        with server(redirect) as (origin,seen):
            with pytest.raises(ValueError):wire.request(origin,REQUEST,timeout=2)
        assert len(seen)==1;assert target_seen==[]


def test_environment_proxy_and_python_hooks_are_not_inherited(monkeypatch):
    with server(message(b'{}')) as (trap,trap_seen),server(message(b'{}')) as (origin,seen):
        monkeypatch.setenv('http_proxy',trap);monkeypatch.setenv('HTTP_PROXY',trap)
        monkeypatch.setenv('NO_PROXY','');monkeypatch.setenv('PYTHONHOME','/nonexistent')
        result=wire.request(origin,REQUEST,timeout=2)
    assert result['body']=={};assert len(seen)==1;assert trap_seen==[]


def test_dripping_body_cannot_extend_whole_request_deadline(monkeypatch):
    processes=[];real=subprocess.Popen
    def start(*a,**kw):
        p=real(*a,**kw);processes.append(p);return p
    monkeypatch.setattr(subprocess,'Popen',start)
    with server(b'',drip=True) as (origin,seen):
        begin=time.monotonic()
        with pytest.raises(ValueError,match='deadline'):wire.request(origin,REQUEST,timeout=.6)
        elapsed=time.monotonic()-begin
    assert elapsed<3 and len(seen)==1
    assert len(processes)==1 and processes[0].poll() is not None


@pytest.mark.parametrize('path',['https://example.invalid/a','//127.0.0.1/x', '/v1/projects/p/../x',
                                 '/v1/projects/p#fragment','/v1/projects/p\nheader'])
def test_request_rejection_never_starts_a_worker(monkeypatch,path):
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('must not spawn'))
    with pytest.raises(ValueError):wire.request('http://127.0.0.1:8080',{**REQUEST,'path':path})


@pytest.mark.parametrize('seconds',[True,0,-1,float('nan'),float('inf'),21,10**400])
def test_invalid_deadline_never_starts_worker(monkeypatch,seconds):
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('must not spawn'))
    with pytest.raises(ValueError):wire.request('http://127.0.0.1:8080',REQUEST,timeout=seconds)


def test_complete_collector_through_fixed_workers_and_real_loopback_http(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    value=plan(); oracle=Transport(value); problems=[];seen=[]
    steps=[('observation',i,o) for i,o in enumerate(value['observation'])
           if o['kind'] not in {'partition-page-token-continuation','partition-reconstruction-range-1'}]
    steps += [('recovery',i,o) for i,o in enumerate(value['recovery'])]
    class Handler(BaseHTTPRequestHandler):
        def perform(self):
            try:
                phase,index,operation=steps[len(seen)]
                body=self.rfile.read(int(self.headers.get('content-length','0')))
                body=json.loads(body) if body else None
                assert self.command == operation['method']
                assert self.path.split('?',1)[0] == operation['path'].split('?',1)[0]
                assert self.headers['Authorization']=='Bearer owner'
                request={'phase':phase,'index':index,'kind':operation['kind'],
                         'method':self.command,'path':self.path,'body':body}
                response=oracle(request);seen.append(request)
                self.send_response(response['status']);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(response['byteCount']));self.end_headers()
                self.wfile.write(response['rawBody'])
            except Exception as error:
                problems.append(type(error).__name__)
                self.send_error(500)
        do_GET=do_POST=do_PATCH=do_DELETE=perform
        def log_message(self,*args):pass
    http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
    try:
        origin=f'http://127.0.0.1:{http.server_port}'
        result=collect_local(value,loopback_transport(origin),tmp_path/'wire-run',origin=origin)
    finally:
        http.shutdown();http.server_close();thread.join(timeout=2)
    assert problems==[] and not thread.is_alive()
    assert len(seen)==35  # 31 observation slots - 2 benign skips + 6 recovery.
    assert result['status']=='pass' and result['cleanup']['complete'] is True
    assert result['raw']['bindings']==35
    assert result['reconstruction']['matches'] is True
