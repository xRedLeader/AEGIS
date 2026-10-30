"""Package boundaries; native installed-service acceptance is a separate CI job."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from aegis_install import config, render_units, source_files, runtime_versions
from aegis_service_entry import prepare_socket
from aegis_supervisor import ExecutionDenied

ROOT=Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.value=json.loads((ROOT/"deployment/install.example.json").read_bytes())

    def test_defaults_are_unconfigured_and_units_are_separate_nonroot_roles(self):
        cfg=config(self.value);self.assertFalse(cfg["configured"])
        units=render_units(cfg)
        self.assertEqual(len(units),4)
        for name,raw in units.items():
            unit=raw.decode()
            for line in ("NoNewPrivileges=yes","ProtectSystem=strict","CapabilityBoundingSet=","UMask=0077"):
                self.assertIn(line,unit)
            self.assertIn("ConditionPathExists=/etc/aegis/enabled",unit)
            self.assertNotIn("RestrictNamespaces=",unit)
            self.assertNotIn("PrivateUsers=",unit)
            self.assertNotIn("User=root",unit)
        self.assertIn(b"ConditionPathExists=/etc/aegis/provider-enabled",units["aegis-provider.service"])
        self.assertIn(b"User=aegis-agent",units["aegis-agent.service"])
        self.assertIn(b"User=aegis-receiver",units["aegis-receiver.service"])

    def test_config_denies_aliases_collisions_injection_and_loose_bounds(self):
        for key,value in (("policy_root","/etc/aegis/../secret"),("policy_root","/etc/aegis%u"),
                          ("state_root","/etc/aegis/state"),("python","/opt/runtime/bin/python;id"),
                          ("memory_max_mb",True),("source_commit","main")):
            bad=copy.deepcopy(self.value);bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ExecutionDenied):config(bad)
        bad=copy.deepcopy(self.value);bad["accounts"]["agent"]["uid"]=bad["accounts"]["operator"]["uid"]
        with self.assertRaises(ExecutionDenied):config(bad)
        bad=copy.deepcopy(self.value);bad["socket_groups"]["gateway"]["gid"]=bad["accounts"]["operator"]["gid"]
        with self.assertRaises(ExecutionDenied):config(bad)

    def test_source_requires_exact_manifest_pin_and_file_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);payload=b"reviewed code\n";(root/"a.py").write_bytes(payload)
            manifest=(hashlib.sha256(payload).hexdigest()+"  a.py\n").encode()
            (root/"SHA256SUMS.txt").write_bytes(manifest)
            pin=hashlib.sha256(manifest).hexdigest()
            self.assertEqual(source_files(root,pin)["a.py"],payload)
            with self.assertRaises(ExecutionDenied):source_files(root,"0"*64)
            (root/"a.py").write_bytes(b"tampered")
            with self.assertRaises(ExecutionDenied):source_files(root,pin)

    @unittest.skipUnless(hasattr(os,"getuid"),"POSIX runtime custody")
    def test_runtime_rejects_nonroot_symlink_target_before_interpreter_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);runtime=base/"runtime";(runtime/"bin").mkdir(parents=True)
            target=base/"external-python";target.write_bytes(b"code");target.chmod(0o644)
            (runtime/"bin/python").symlink_to(target)
            original=Path.stat
            def custody(path,*args,**kwargs):
                values=list(original(path,*args,**kwargs));values[4]=123 if path==target else 0
                return os.stat_result(values)
            with patch.object(Path,"stat",custody),patch("aegis_install.protected_parents"),patch("aegis_install.command") as command:
                with self.assertRaisesRegex(ExecutionDenied,"symlink target is not root-owned"):
                    runtime_versions({"python":str(runtime/"bin/python")},{"deployment/requirements.lock":b"attrs==26.1.0\n"})
                command.assert_not_called()

    @unittest.skipUnless(hasattr(os,"getuid"),"POSIX runtime custody")
    def test_runtime_rejects_external_directory_symlink_before_interpreter_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);runtime=base/"runtime";(runtime/"bin").mkdir(parents=True)
            target=base/"external-library";target.mkdir();(runtime/"lib").symlink_to(target,target_is_directory=True)
            original=Path.stat
            def custody(path,*args,**kwargs):
                values=list(original(path,*args,**kwargs));values[4]=0;return os.stat_result(values)
            with patch.object(Path,"stat",custody),patch("aegis_install.protected_parents"),patch("aegis_install.command") as command:
                with self.assertRaisesRegex(ExecutionDenied,"directory symlink escapes"):
                    runtime_versions({"python":str(runtime/"bin/python")},{"deployment/requirements.lock":b"attrs==26.1.0\n"})
                command.assert_not_called()

    @unittest.skipUnless(hasattr(os,"getuid") and hasattr(socket,"AF_UNIX"),"Linux socket custody")
    def test_socket_restart_removes_only_stale_owned_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o710);path=root/"service.sock"
            server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            server.bind(str(path));path.chmod(0o660);server.listen(1)
            with self.assertRaises(ExecutionDenied):prepare_socket(path,os.getuid(),os.getgid())
            self.assertTrue(path.exists());server.close()
            prepare_socket(path,os.getuid(),os.getgid());self.assertFalse(path.exists())
            path.write_text("preserve")
            with self.assertRaises(ExecutionDenied):prepare_socket(path,os.getuid(),os.getgid())
            self.assertEqual(path.read_text(),"preserve")
            path.unlink();path.symlink_to(root/"missing")
            with self.assertRaises(ExecutionDenied):prepare_socket(path,os.getuid(),os.getgid())
            self.assertTrue(path.is_symlink())
