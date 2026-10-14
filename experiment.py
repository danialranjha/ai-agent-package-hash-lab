"""Offline pip integrity experiment. Only generated inert wheels are supported."""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import zipfile

NAME = 'hash_fixture'
VERSION = '1.0'
WHEEL = f'{NAME}-{VERSION}-py3-none-any.whl'
METHODS = ('version_only', 'saved_hash', 'fresh_hash')
VARIANTS = ('original', 'changed_data', 'benign_metadata')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wheel_bytes(variant):
    """No entry points, dependencies, executable payload or build scripts."""
    if variant not in VARIANTS:
        raise ValueError(variant)
    info = f'{NAME}-{VERSION}.dist-info'
    files = {
        f'{NAME}/__init__.py': b'',
        f'{NAME}/value.txt': b'99\n' if variant == 'changed_data' else b'42\n',
        f'{info}/METADATA': (
            'Metadata-Version: 2.1\nName: hash-fixture\nVersion: 1.0\n'
            + ('Summary: Ordinary wording edit\n' if variant == 'benign_metadata'
               else 'Summary: Inert local fixture\n')
        ).encode(),
        f'{info}/WHEEL': b'Wheel-Version: 1.0\nGenerator: local-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    record = io.StringIO(newline='')
    writer = csv.writer(record, lineterminator='\n')
    for name, data in sorted(files.items()):
        h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256=' + h, str(len(data))])
    writer.writerow([f'{info}/RECORD', '', ''])
    files[f'{info}/RECORD'] = record.getvalue().encode()
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            zi = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            archive.writestr(zi, data)
    return result.getvalue()


def child_env():
    # Drop inherited tokens, proxy settings and pip options. Disable config files.
    return {'PATH': os.defpath, 'PIP_CONFIG_FILE': os.devnull,
            'LC_ALL': 'C', 'PYTHONIOENCODING': 'utf-8'}


def invoke(argv, cwd):
    return subprocess.run(argv, cwd=cwd, env=child_env(), text=True,
                          capture_output=True, timeout=60, check=False)


def run_experiment():
    original_hash = digest(wheel_bytes('original'))
    rows = []
    with tempfile.TemporaryDirectory(prefix='package-hash-lab-') as temp:
        root = Path(temp).resolve()
        version = invoke([sys.executable, '-I', '-m', 'pip', '--version'], root)
        if version.returncode:
            raise RuntimeError('pip is required before running this offline lab')
        pip_version = version.stdout.split()[1]
        for variant in VARIANTS:
            data = wheel_bytes(variant)
            for method in METHODS:
                case = root / variant / method
                wheelhouse = case / 'wheelhouse'
                wheelhouse.mkdir(parents=True)
                (wheelhouse / WHEEL).write_bytes(data)
                expected_hash = (original_hash if method == 'saved_hash' else
                                 digest(data) if method == 'fresh_hash' else None)
                req = 'hash-fixture==1.0'
                if expected_hash:
                    req += ' --hash=sha256:' + expected_hash
                requirements = case / 'requirements.txt'
                requirements.write_text(req + '\n')
                target = case / 'installed'
                argv = [sys.executable, '-I', '-m', 'pip', 'install',
                        '--no-index', '--find-links', str(wheelhouse),
                        '--no-deps', '--only-binary=:all:', '--no-compile',
                        '--no-cache-dir', '--disable-pip-version-check',
                        '--target', str(target), '-r', str(requirements)]
                if method != 'version_only':
                    argv.append('--require-hashes')
                proc = invoke(argv, case)
                value_path = target / NAME / 'value.txt'
                value = value_path.read_text() if value_path.exists() else None
                target_files = sorted(str(p.relative_to(target)) for p in target.rglob('*')
                                      if p.is_file()) if target.exists() else []
                expected_accept = method != 'saved_hash' or variant == 'original'
                expected_value = ('99\n' if variant == 'changed_data' else '42\n') if expected_accept else None
                hash_error = 'DO NOT MATCH THE HASHES' in proc.stderr
                valid = ((proc.returncode == 0) == expected_accept and value == expected_value
                         and (expected_accept or (hash_error and not target_files)))
                normalize = lambda text: text.replace(str(root), '<WORK>').replace(sys.executable, '<PYTHON>')
                rows.append({
                    'variant': variant, 'method': method,
                    'package_name': 'hash-fixture', 'package_version': VERSION,
                    'archive_sha256': digest(data), 'expected_sha256': expected_hash,
                    'requirements': req, 'command': [normalize(a) for a in argv],
                    'returncode': proc.returncode, 'stdout': normalize(proc.stdout),
                    'stderr': normalize(proc.stderr), 'hash_mismatch': hash_error,
                    'installed_value': value, 'installed_files': target_files,
                    'expected_accept': expected_accept, 'expectation_met': valid,
                    'events': ['generate_inert_archive',
                               'reuse_original_hash' if method == 'saved_hash' else
                               'derive_hash_from_current_archive' if method == 'fresh_hash' else 'pin_version_only',
                               'run_real_pip', 'inspect_target_without_import'],
                })
    return {'schema_version': 1, 'runtime': {'python': platform.python_version(), 'pip': pip_version},
            'scope': 'Three authored archives, three install policies, nine local pip invocations; no model, network or fixture import.',
            'original_sha256': original_hash, 'rows': rows,
            'all_expectations_met': all(r['expectation_met'] for r in rows)}


def evidence(result):
    lines = ['# Measured install outcomes', '',
             'Nine invocations: three authored archive variants × three policies. One run per cell, not an attack-rate estimate.', '',
             '| Archive | Version only | Saved hash | Fresh hash |', '|---|---|---|---|']
    for variant in VARIANTS:
        cells = []
        for method in METHODS:
            row = next(r for r in result['rows'] if r['variant'] == variant and r['method'] == method)
            cells.append('installed ' + row['installed_value'].strip() if row['returncode'] == 0
                         else 'hash mismatch; no installed files')
        lines.append('| ' + ' | '.join([variant] + cells) + ' |')
    lines += ['', 'The changed-data archive retains the same name and version. Saved hash uses the original archive digest; Fresh hash uses a newly calculated digest of the archive currently supplied. Both hash methods use the same pip verification options.', '',
              'An ordinary metadata edit is also rejected by Saved hash. Matching bytes is not a test for malicious intent. Fresh hash accepting changed bytes exposes the trust-acquisition limit, not a SHA-256 failure.', '',
              'No package was imported. The sink is the installed value.txt read by the trusted harness. The empty __init__.py contains no executable statements. See run.json for exact hashes, requirements, commands, normalized pip logs and target file lists.', '']
    return '\n'.join(lines)


def save(result, directory=Path('artifacts')):
    directory.mkdir(exist_ok=True)
    (directory / 'run.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    (directory / 'evidence.md').write_text(evidence(result))


if __name__ == '__main__':
    result = run_experiment()
    save(result)
    print(json.dumps({'rows': len(result['rows']), 'all_expectations_met': result['all_expectations_met'],
                      'runtime': result['runtime']}))
    sys.exit(0 if result['all_expectations_met'] else 1)
