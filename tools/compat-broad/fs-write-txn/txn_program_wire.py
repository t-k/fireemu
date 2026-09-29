"""Pinned, bounded one-call Node child for the shared graph (REST or native gRPC); callers must authorize and charge first."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

from txn_sandbox_runtime import PYTHON_VERSION, require_packet_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORKER = HERE / 'txn_program_transport.mjs'
LOCK = ROOT / 'conformance/pnpm-lock.yaml'
_ENV = {'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
_SEEDS = {'@grpc/grpc-js', '@google-cloud/firestore'}
_RUNTIME_STAMPS = {}


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _tree(root):
    root = Path(root)
    rows = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != 'node_modules')
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise ValueError('program dependency tree has a non-regular entry')
        for name in files:
            path = Path(directory) / name
            if not path.is_file():
                raise ValueError('program dependency entry is not a file')
            rows.append((path.relative_to(root).as_posix(), _sha(path)))
    rows.sort()
    return len(rows), hashlib.sha256(''.join(f'{name}\0{digest}\n' for name, digest in rows).encode()).hexdigest()


def discover_runtime(executable):
    require_packet_runtime(PYTHON_VERSION)
    node = Path(executable)
    if not node.is_absolute() or not node.is_file():
        raise ValueError('program absolute Node executable required')
    result = subprocess.run([str(node), str(WORKER), '--runtime-info'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_ENV, timeout=12, check=True)
    if len(result.stdout) > 65536:
        raise ValueError('program runtime receipt capacity exceeded')
    info = json.loads(result.stdout)
    runtime = {**info, 'nodeExecutable': str(node), 'nodeSha256': _sha(node), 'workerSha256': _sha(WORKER), 'lockSha256': _sha(LOCK), 'pythonVersion': PYTHON_VERSION, 'pythonExecutable': sys.executable, 'pythonSha256': _sha(sys.executable)}
    verify_runtime(runtime)
    return runtime


def _stamp(path):
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return None
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    try:
        referent = Path(path).stat()
    except FileNotFoundError:
        referent = None
    # Both the link and the bytes opened through it must remain unchanged.
    return identity(info), identity(referent) if referent else None


def _watch_paths(value):
    paths = {WORKER, LOCK, Path(sys.executable), Path(value['nodeExecutable'])}
    modules = ROOT / 'conformance/node_modules'
    paths.add(modules)
    for row in value['dependencies'].values():
        root = Path(row['root'])
        for directory, dirs, files in os.walk(root, followlinks=False):
            paths.add(Path(directory))
            paths.update(Path(directory) / name for name in dirs + files)
            dirs[:] = [name for name in dirs if name != 'node_modules']
        for name in row['requires']:
            for parent in [root, *root.parents]:
                if parent.name != 'node_modules':
                    candidate = parent / 'node_modules' / name
                    paths.update([candidate, candidate.parent, parent / 'node_modules'])
                if parent == ROOT: break
    return tuple(sorted(map(str, paths)))


def verify_runtime(value):
    """Hash every byte initially, then reject any inode/ctime or resolution-path change.

    The cache contains only file identity stamps, never an authorization decision.
    Runtime trees are read-only during a recording; even unrelated changes stop it.
    """
    require_packet_runtime(PYTHON_VERSION)
    if not isinstance(value, dict) or value.get('pythonExecutable') != sys.executable or value.get('pythonVersion') != PYTHON_VERSION:
        raise ValueError('program runtime differs from the running interpreter')
    key = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    cached = _RUNTIME_STAMPS.get(key)
    if cached is not None:
        paths, before = cached
        if tuple(_stamp(path) for path in paths) != before:
            raise ValueError('program reviewed runtime or dependency resolution path changed')
        return
    _verify_runtime_full(value)
    paths = _watch_paths(value)
    before = tuple(_stamp(path) for path in paths)
    # Bracket the second byte verification to refuse a racing file replacement.
    _verify_runtime_full(value)
    after = tuple(_stamp(path) for path in paths)
    if before != after:
        raise ValueError('program runtime changed while its bytes were verified')
    if len(_RUNTIME_STAMPS) >= 4: _RUNTIME_STAMPS.clear()
    _RUNTIME_STAMPS[key] = (paths, after)


def _verify_runtime_full(value):
    require_packet_runtime(PYTHON_VERSION)
    expected_keys = {'nodeVersion', 'dependencies', 'nodeExecutable', 'nodeSha256', 'workerSha256', 'lockSha256', 'pythonVersion', 'pythonExecutable', 'pythonSha256'}
    if not isinstance(value, dict) or set(value) != expected_keys or value['pythonVersion'] != PYTHON_VERSION or value['pythonExecutable'] != sys.executable or value['nodeVersion'] != 'v24.14.0':
        raise ValueError('program runtime differs from reviewed interpreter')
    node = Path(value['nodeExecutable'])
    if not node.is_absolute() or not node.is_file():
        raise ValueError('program reviewed Node executable missing')
    actual_version = subprocess.run([str(node), '--version'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_ENV, timeout=2, check=True).stdout
    if actual_version != b'v24.14.0\n':
        raise ValueError('program actual Node version differs')
    for key, path in [('nodeSha256', node), ('workerSha256', WORKER), ('lockSha256', LOCK), ('pythonSha256', sys.executable)]:
        if value[key] != _sha(path):
            raise ValueError('program runtime bytes differ')
    dependencies = value['dependencies']
    if not isinstance(dependencies, dict) or not _SEEDS <= set(dependencies):
        raise ValueError('program closed dependency roots differ')
    modules = ROOT / 'conformance/node_modules'
    for key, row in dependencies.items():
        if not isinstance(row, dict) or set(row) != {'root', 'name', 'version', 'requires', 'fileCount', 'treeSha256'}:
            raise ValueError('program dependency receipt differs')
        root = modules / key
        if not isinstance(key, str) or '..' in Path(key).parts or Path(key).is_absolute() or row['root'] != str(root) or not root.is_dir() or not root.resolve().is_relative_to(modules.resolve()):
            raise ValueError('program dependency comes from another checkout')
        package = json.loads((root / 'package.json').read_text())
        count, digest = _tree(root)
        if package['name'] != row['name'] or package['version'] != row['version'] or type(row['fileCount']) is not int or count != row['fileCount'] or digest != row['treeSha256']:
            raise ValueError('program actual dependency bytes differ')
        names = set(package.get('dependencies', {})) | set(package.get('optionalDependencies', {}))
        if not isinstance(row['requires'], dict) or set(row['requires']) != names:
            raise ValueError('program actual dependency graph differs')
        for name in names:
            resolved = None
            for parent in [root, *root.parents]:
                if parent.name == 'node_modules': continue
                candidate = parent / 'node_modules' / name
                if (candidate / 'package.json').is_file():
                    resolved = candidate.resolve().relative_to(modules.resolve()).as_posix()
                    break
            if resolved != row['requires'][name] or resolved is not None and resolved not in dependencies or resolved is None and name not in package.get('optionalDependencies', {}):
                raise ValueError('program dependency resolution changed or was omitted')
    reachable = set()
    pending = list(_SEEDS)
    while pending:
        key = pending.pop()
        if key in reachable: continue
        reachable.add(key)
        pending.extend(child for child in dependencies[key]['requires'].values() if child is not None)
    if reachable != set(dependencies): raise ValueError('program dependency graph is not closed')
    if dependencies['@grpc/grpc-js']['version'] != '1.14.4' or dependencies['@google-cloud/firestore']['version'] != '8.7.1':
        raise ValueError('program dependency versions differ')


class NodeWire:
    """No send retries; a transport failure preserves an unknown outcome."""

    def __init__(self, runtime, scope, *, target=None):
        verify_runtime(runtime)
        self.runtime = copy.deepcopy(runtime)
        if not isinstance(scope, dict) or set(scope) != {'slug', 'documents', 'states'}:
            raise ValueError('program scope differs')
        self.scope = copy.deepcopy(scope)
        self.target = copy.deepcopy(target or {'kind': 'production'})
        self.last_lifecycle = None

    def _terminate(self, child):
        if child.poll() is not None:
            return
        proof = subprocess.run(['ps', '-p', str(child.pid), '-o', 'comm=', '-o', 'args='], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_ENV, timeout=2, check=False).stdout.decode()
        if Path(self.runtime['nodeExecutable']).name not in proof or str(WORKER) not in proof:
            raise RuntimeError('program child ownership could not be verified')
        child.terminate()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proof = subprocess.run(['ps', '-p', str(child.pid), '-o', 'comm=', '-o', 'args='], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_ENV, timeout=2, check=False).stdout.decode()
            if str(WORKER) not in proof:
                raise RuntimeError('program child identity changed during termination')
            child.kill()
            child.wait(timeout=2)

    def _child(self, spec, timeout):
        payload = json.dumps(spec, separators=(',', ':'), allow_nan=False).encode()
        if len(payload) > 16384:
            raise ValueError('program private IPC payload exceeds capacity')
        child = subprocess.Popen([self.runtime['nodeExecutable'], str(WORKER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_ENV, close_fds=True)
        deadline = time.monotonic() + timeout
        output = bytearray()
        error = None
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(child.stdin.fileno(), False)
                os.set_blocking(child.stdout.fileno(), False)
                selector.register(child.stdin, selectors.EVENT_WRITE)
                selector.register(child.stdout, selectors.EVENT_READ)
                offset = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('program IPC deadline exceeded')
                    for key, _events in selector.select(min(remaining, 0.2)):
                        if key.fileobj is child.stdin:
                            offset += os.write(child.stdin.fileno(), payload[offset:])
                            if offset == len(payload):
                                selector.unregister(child.stdin)
                                child.stdin.close()
                        else:
                            block = os.read(child.stdout.fileno(), 4096)
                            if not block:
                                selector.unregister(child.stdout)
                            else:
                                output.extend(block)
                                if len(output) > 65536:
                                    raise ValueError('program IPC response exceeds capacity')
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
            if child.returncode != 0:
                raise ValueError('program worker did not return a native receipt')
            receipt = json.loads(output)
        except (ValueError, TimeoutError, OSError, subprocess.TimeoutExpired):
            error = True
            receipt = {'kind': 'txn-program-receipt-v1', 'transport': spec['transport'], 'complete': False, 'code': 2, 'details': 'worker IPC incomplete', 'response': None, 'http': None, 'dispatchedRequests': 1}
        finally:
            try:
                self._terminate(child)
            finally:
                for pipe in [child.stdin, child.stdout]:
                    if pipe and not pipe.closed:
                        pipe.close()
        lifecycle = {'childPid': child.pid, 'childReaped': child.poll() is not None, 'workerExitCode': child.returncode, 'ipcComplete': error is None}
        self.last_lifecycle = lifecycle
        return receipt, lifecycle

    def send(self, transport, method, request, *, nonce, owner_id, bearer, deadline_ms=10000):
        verify_runtime(self.runtime)
        writer = method == 'Commit' and 'transaction' not in request
        if transport not in ('rest', 'grpc') or type(deadline_ms) is not int or not 1 <= deadline_ms <= (30000 if writer else 10000):
            raise ValueError('program transport or deadline differs')
        project = 'fireemu-oracle-sbx'
        body = copy.deepcopy(request)
        if self.target.get('kind') == 'local':
            project = 'demo-program'
            # Rebase only the declared database and document fields for local proof.
            production = 'projects/fireemu-oracle-sbx/databases/(default)'
            local = f'projects/{project}/databases/(default)'
            for key in ['database', 'name']:
                if key in body:
                    body[key] = body[key].replace(production, local, 1)
            for write in body.get('writes', []):
                write['update']['name'] = write['update']['name'].replace(production, local, 1)
        spec = {'kind': 'txn-program-call-v1', 'transport': transport, 'target': self.target, 'projectId': project, 'nonce': nonce, 'ownerId': owner_id, **copy.deepcopy(self.scope), 'method': method, 'request': body, 'bearer': bearer, 'deadlineMs': deadline_ms}
        receipt, lifecycle = self._child(spec, deadline_ms / 1000 + 5)
        required = {'kind', 'transport', 'complete', 'code', 'details', 'response', 'http', 'dispatchedRequests'}
        if not isinstance(receipt, dict) or set(receipt) != required or receipt['kind'] != 'txn-program-receipt-v1' or receipt['transport'] != transport or type(receipt['code']) is not int or not 0 <= receipt['code'] <= 16 or type(receipt['complete']) is not bool or type(receipt['dispatchedRequests']) is not int or receipt['dispatchedRequests'] != 1:
            raise ValueError('program closed native receipt differs')
        if receipt['http'] is not None and (type(receipt['http']) is not int or not 100 <= receipt['http'] <= 599) or transport == 'grpc' and receipt['http'] is not None:
            raise ValueError('program HTTP status differs from its transport')
        if receipt['complete'] and receipt['code'] in [1, 2, 4, 13, 14]:
            raise ValueError('program indeterminate status claimed complete')
        if not isinstance(receipt['details'], str) or len(receipt['details'].encode()) > 16384 or (receipt['code'] == 0 and receipt['complete'] and not isinstance(receipt['response'], dict)):
            raise ValueError('program native result is malformed')
        if len(bearer) > 10 and bearer in json.dumps(receipt):
            raise ValueError('program native receipt echoed a credential')
        if not lifecycle.get('childReaped'):
            raise ValueError('program worker remains live')
        result = {**receipt, **lifecycle}
        if self.target.get('kind') == 'local' and method == 'GetDocument' and result['code'] == 0 and isinstance(result['response'], dict):
            result['localWireResponse'] = copy.deepcopy(result['response'])
            result['localNameRebased'] = False
            if result['response'].get('name') == body.get('name'):
                result['response']['name'] = request['name']
                result['localNameRebased'] = True
        return result
