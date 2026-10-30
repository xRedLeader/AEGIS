"""Explicit online preparation for disposable CI; execution itself stays offline."""
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tarfile
import urllib.request
from urllib.parse import urlsplit
import zipfile

ROOT=Path('/srv/aegis-native-tools')
PINS={
    'gitleaks':('https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_linux_x64.tar.gz',
                '9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c','e18325d568268b6efb6cd0cc721f8bea5667f4cd1c8d03618ab61987f41269ad'),
    'trivy':('https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz',
             'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0','d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83')}


def download(url,limit):
    parsed=urlsplit(url)
    assert parsed.scheme=='https' and parsed.hostname in {'github.com','pypi.org','files.pythonhosted.org'} and not parsed.username and not parsed.password
    with urllib.request.urlopen(url,timeout=90) as response:
        assert urlsplit(response.geturl()).hostname in {'github.com','pypi.org','files.pythonhosted.org','release-assets.githubusercontent.com','objects.githubusercontent.com'}
        data=response.read(limit+1)
    assert 0<len(data)<=limit,'download exceeds preparation bound'
    return data


def write_binary(name,data,expected):
    assert hashlib.sha256(data).hexdigest()==expected,'executable differs from reviewed binary'
    path=ROOT/name;path.write_bytes(data);path.chmod(0o555)


def file_sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as stream:
        while chunk:=stream.read(16*1024**2):digest.update(chunk)
    return digest.hexdigest()


def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','ephemeral GitHub Actions preparation only'
    assert not ROOT.exists(),'refuse existing tool directory'
    ROOT.mkdir(mode=0o755)
    source=Path(__file__).resolve().parents[1];installed_source=Path('/srv/aegis-native-source')
    assert not installed_source.exists(),'refuse existing source fixture'
    manifest=(source/'SHA256SUMS.txt').read_bytes()
    installed_source.mkdir(mode=0o755)
    for line in manifest.decode('ascii').splitlines():
        expected,name=line.split('  ',1);relative=Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts and re.fullmatch('[a-f0-9]{64}',expected)
        raw=(source/relative).read_bytes();assert hashlib.sha256(raw).hexdigest()==expected
        destination=installed_source/relative;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(raw);destination.chmod(0o444)
    (installed_source/'SHA256SUMS.txt').write_bytes(manifest);(installed_source/'SHA256SUMS.txt').chmod(0o444)
    for name,(url,archive_sha,binary_sha) in PINS.items():
        data=download(url,80*1024**2);assert hashlib.sha256(data).hexdigest()==archive_sha
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member=archive.getmember(name);assert member.isfile() and member.size<=224*1024**2
            write_binary(name,archive.extractfile(member).read(),binary_sha)
    index=json.loads(download('https://pypi.org/pypi/semgrep/1.125.0/json',2*1024**2))
    wheel=next(item for item in index['urls'] if item['filename'].endswith('.whl') and 'manylinux' in item['filename'] and 'x86_64' in item['filename'])
    data=download(wheel['url'],100*1024**2);assert hashlib.sha256(data).hexdigest()==wheel['digests']['sha256']
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        name='semgrep/bin/semgrep-core';assert archive.getinfo(name).file_size==201603720
        write_binary('semgrep-core',archive.read(name),'313bf3bbb50648fb5c3f43bd1d72dfee28dae436e10a096acb7d9a5839d18f11')
    data=download('https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip',100*1024**2)
    assert hashlib.sha256(data).hexdigest()=='1526650021ada87e9cfc2a30048c8e59f5db9eed079c7807d53b7e181009bfe4'
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.getinfo('nuclei').file_size<=224*1024**2
        write_binary('nuclei',archive.read('nuclei'),'63f881a5b1df284710daf02e880f3ceaf0eca269e0885dd860d0f31715153a9c')
    account=pwd.getpwnam('aegis-native-test')
    cache=Path('/srv/aegis-native-db-preparation');cache.mkdir(mode=0o700);os.chown(cache,account.pw_uid,account.pw_gid)
    # This separately named preparation step is the only scanner-related network
    # operation. No assessed source, signing keys or provider credentials enter it.
    subprocess.run(['/usr/sbin/runuser','-u',account.pw_name,'--','/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME=/nonexistent',
                    str(ROOT/'trivy'),'image','--download-db-only','--db-repository','ghcr.io/aquasecurity/trivy-db:2',
                    '--cache-dir',str(cache),'--no-progress','--quiet'],check=True,timeout=180)
    source=cache/'db';assert {p.name for p in source.iterdir()}=={'metadata.json','trivy.db'}
    target=ROOT/'trivy-db';target.mkdir(mode=0o755)
    for name in ('trivy.db','metadata.json'):
        assert not (source/name).is_symlink() and (source/name).is_file()
        assert 0<(source/name).stat().st_size<=(2*1024**3 if name=='trivy.db' else 4096)
        shutil.copyfile(source/name,target/name);(target/name).chmod(0o444)
    # Retain the reviewed root-owned copy, not a second multi-gigabyte cache.
    folder=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in ('trivy.db','metadata.json'):os.unlink(name,dir_fd=folder)
    finally:os.close(folder)
    source.rmdir();cache.rmdir()
    subprocess.run(['/usr/bin/gcc','-static','-O2','-Wall','-Wextra','tests/fixtures/native_scanner_probe.c','-o',str(ROOT/'native-probe')],check=True,timeout=60)
    (ROOT/'native-probe').chmod(0o555)
    subprocess.run(['/usr/bin/gcc','-static','-O2','-Wall','-Wextra','-DAEGIS_SEMGREP_PROFILE','tests/fixtures/native_scanner_probe.c',
                    '-o',str(ROOT/'semgrep-probe')],check=True,timeout=60)
    (ROOT/'semgrep-probe').chmod(0o555)
    subprocess.run(['/usr/bin/gcc','-static','-O2','-Wall','-Wextra','-DAEGIS_TRIVY_PROFILE','tests/fixtures/native_scanner_probe.c',
                    '-o',str(ROOT/'trivy-probe')],check=True,timeout=60)
    (ROOT/'trivy-probe').chmod(0o555)
    proof={'source_commit':os.environ['AEGIS_TEST_COMMIT'],'source_manifest_sha256':hashlib.sha256(manifest).hexdigest(),
           'binary_sha256':{name:file_sha(ROOT/name) for name in ('gitleaks','trivy','semgrep-core','nuclei','native-probe','semgrep-probe','trivy-probe')},
           'database_sha256':{name:file_sha(target/name) for name in ('trivy.db','metadata.json')},
           'database_metadata':json.loads((target/'metadata.json').read_bytes()),'database_repository':'ghcr.io/aquasecurity/trivy-db:2',
           'semgrep_wheel_sha256':wheel['digests']['sha256']}
    print(json.dumps(proof,sort_keys=True))


if __name__=='__main__':main()
