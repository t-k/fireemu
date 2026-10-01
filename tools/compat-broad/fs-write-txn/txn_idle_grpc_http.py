"""Exactly one fixed REST request per isolated metadata or OAuth worker."""

from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode

PROJECT = 'fireemu-oracle-sbx'
SELF = Path(__file__).resolve()


def _secret(value, limit=8192):
    return isinstance(value, str) and 0 < len(value) <= limit and all(33 <= ord(char) <= 126 for char in value)


def worker_call(value):
    if not isinstance(value, dict) or set(value) != {'slot', 'secret', 'resource'}:
        raise ValueError('closed P10-A REST worker schema required')
    slot, secret, resource = value['slot'], value['secret'], value['resource']
    body = None
    headers = {}
    method = 'GET'
    if slot == 'refresh':
        if resource is not None or not isinstance(secret, dict) or set(secret) != {'type', 'client_id', 'client_secret', 'refresh_token'} or secret['type'] != 'authorized_user' or not all(_secret(secret[key]) for key in ['client_id', 'client_secret', 'refresh_token']):
            raise ValueError('P10-A authorized-user refresh schema differs')
        host, path, method = 'oauth2.googleapis.com', '/token', 'POST'
        body = urlencode({'grant_type': 'refresh_token', **{key: secret[key] for key in ['client_id', 'client_secret', 'refresh_token']}}).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    else:
        if not _secret(secret): raise ValueError('P10-A bounded bearer required')
        if slot != 'ruleset-source' and resource is not None: raise ValueError('P10-A REST resource override refused')
        if slot == 'oauth-tokeninfo':
            host, path = 'www.googleapis.com', '/oauth2/v1/tokeninfo?' + urlencode({'access_token': secret})
        elif slot == 'project':
            host, path = 'cloudresourcemanager.googleapis.com', f'/v1/projects/{PROJECT}'
        elif slot == 'database':
            host, path = 'firestore.googleapis.com', f'/v1/projects/{PROJECT}/databases/(default)'
        elif slot == 'rules-release':
            host, path = 'firebaserules.googleapis.com', f'/v1/projects/{PROJECT}/releases/cloud.firestore'
        elif slot == 'ruleset-source' and isinstance(resource, str) and re.fullmatch(rf'projects/{PROJECT}/rulesets/[A-Za-z0-9_-]+', resource):
            host, path = 'firebaserules.googleapis.com', f'/v1/{resource}'
        else:
            raise ValueError('P10-A REST slot or ruleset differs')
        if slot != 'oauth-tokeninfo': headers = {'Authorization': 'Bearer ' + secret, 'x-goog-user-project': PROJECT}
    connection = http.client.HTTPSConnection(host, timeout=11)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536 or response.status != 200 or response.getheader('Content-Type').split(';', 1)[0].strip().lower() != 'application/json':
            return {'complete': False, 'status': response.status, 'body': None}
        decoded = json.loads(raw)
        return {'complete': isinstance(decoded, dict), 'status': response.status, 'body': decoded}
    finally:
        connection.close()


def request_once(slot, secret, resource=None):
    """Secrets enter stdin; returned OAuth bodies must never be journaled."""
    payload = json.dumps({'slot': slot, 'secret': secret, 'resource': resource}, separators=(',', ':')).encode()
    if len(payload) > 24576: raise ValueError('P10-A REST IPC request capacity exceeded')
    command = [sys.executable, '-I', '-S', '-B', str(SELF), '--worker']
    worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={'LANG': 'C', 'LC_ALL': 'C'}, close_fds=True)
    try:
        output, _unused = worker.communicate(payload, timeout=13)
        if worker.returncode != 0 or len(output) > 65536:
            raise ValueError('P10-A fixed REST worker failed')
        receipt = json.loads(output)
        if not isinstance(receipt, dict) or set(receipt) != {'complete', 'status', 'body'} or type(receipt['complete']) is not bool or type(receipt['status']) is not int:
            raise ValueError('P10-A fixed REST receipt differs')
        return {**receipt, 'workerReaped': True}
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return {'complete': False, 'status': None, 'body': None, 'workerReaped': False}
    finally:
        if worker.poll() is None:
            identity = subprocess.run(['ps', '-p', str(worker.pid), '-o', 'comm=', '-o', 'args='], capture_output=True, text=True, timeout=2, check=False).stdout
            if Path(sys.executable).name not in identity or str(SELF) not in identity:
                raise RuntimeError('P10-A REST worker PID ownership differs')
            worker.terminate()
            try: worker.wait(timeout=1)
            except subprocess.TimeoutExpired:
                identity = subprocess.run(['ps', '-p', str(worker.pid), '-o', 'comm=', '-o', 'args='], capture_output=True, text=True, timeout=2, check=False).stdout
                if str(SELF) not in identity: raise RuntimeError('P10-A REST worker PID changed')
                worker.kill(); worker.wait(timeout=2)
        for pipe in [worker.stdin, worker.stdout]:
            if pipe and not pipe.closed: pipe.close()


def refresh(baseline, budget, *, before_send):
    before_send()
    budget.charge('credential')
    path = Path.home() / '.config/gcloud/application_default_credentials.json'
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 24576:
        raise ValueError('P10-A fixed authorized-user configuration missing')
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get('type') != 'authorized_user' or value.get('client_id') != baseline['credentialPrincipal']['clientId']:
        raise ValueError('P10-A authorized-user client differs from baseline')
    secret = {key: value[key] for key in ['type', 'client_id', 'client_secret', 'refresh_token']}
    before_send()
    result = request_once('refresh', secret)
    body = result.get('body') or {}
    if result.get('complete') is not True or result.get('workerReaped') is not True or body.get('token_type') != 'Bearer' or type(body.get('expires_in')) is not int or body['expires_in'] < 1600 or not _secret(body.get('access_token')):
        raise ValueError('P10-A single REST refresh is incomplete or insufficient')
    return body['access_token']


if __name__ == '__main__':
    if sys.argv[1:] != ['--worker'] or sys.version_info[:3] != (3, 12, 13): raise SystemExit(2)
    raw = sys.stdin.buffer.read(24577)
    if len(raw) > 24576: raise SystemExit(2)
    result = worker_call(json.loads(raw))
    output = json.dumps(result, separators=(',', ':')).encode()
    if len(output) > 65536: raise SystemExit(2)
    sys.stdout.buffer.write(output + b'\n')
