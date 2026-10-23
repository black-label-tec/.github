import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('integrity',Path(__file__).with_name('integrity.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.git('init','-q');self.git('config','user.email','test@example.invalid');self.git('config','user.name','Test')
        self.write('README.md','initial\n');self.commit();self.base=self.git('rev-parse','HEAD')
    def tearDown(self): self.temp.cleanup()
    def git(self,*args): return subprocess.check_output(['git','-C',str(self.root),*args],stderr=subprocess.DEVNULL).decode().strip()
    def write(self,path,text):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    def commit(self): self.git('add','-A');self.git('commit','-qm','test')
    def changed(self,path='good.txt',text='safe\n'):
        self.write(path,text);self.commit();return module.audit(self.root,self.base)
    def test_clean_change(self):
        r=self.changed();self.assertEqual(r['status'],'passed');self.assertFalse(r['release_authorized']);self.assertEqual(r['runtime_acceptance'],'not_checked')
    def test_reads_committed_bytes_not_worktree(self):
        self.changed();self.write('good.txt','ghp_'+'a'*36)
        self.assertEqual(module.audit(self.root,self.base)['status'],'passed')
    def test_full_head_identity(self):
        r=self.changed();self.assertEqual(r['source_revision'],self.git('rev-parse','HEAD'))
    def test_new_token_blocked_without_leak(self):
        token='ghp_'+'a'*36;r=self.changed(text=token)
        self.assertEqual(r['status'],'failed');self.assertNotIn(token,json.dumps(r))
    def test_new_private_key_blocked(self): self.assertEqual(self.changed(text='-----BEGIN PRIVATE KEY-----')['status'],'failed')
    def test_removed_token_not_blocked(self):
        self.write('old.txt','ghp_'+'a'*36);self.commit();self.base=self.git('rev-parse','HEAD')
        self.write('old.txt','removed');self.commit();self.assertEqual(module.audit(self.root,self.base)['status'],'passed')
    def test_unchanged_legacy_token_not_blocked(self):
        self.write('old.txt','ghp_'+'a'*36+'\noriginal\n');self.commit();self.base=self.git('rev-parse','HEAD')
        self.write('old.txt','ghp_'+'a'*36+'\nchanged\n');self.commit();self.assertEqual(module.audit(self.root,self.base)['status'],'passed')
    def test_initial_commit(self): self.assertEqual(module.audit(self.root)['status'],'passed')
    def test_zero_base_uses_parent(self): self.changed();self.assertEqual(module.audit(self.root,'0'*40)['base_revision'],self.base)
    def test_invalid_sha(self):
        with self.assertRaises(ValueError):module.audit(self.root,'--help')
    def test_same_revision_rejected(self):
        with self.assertRaises(ValueError):module.audit(self.root,self.base)
    def test_unrelated_base_rejected(self):
        self.git('checkout','--orphan','other');self.write('other.txt','x');self.commit();other=self.git('rev-parse','HEAD');self.git('checkout','master')
        with self.assertRaises(ValueError):module.audit(self.root,other)
    def test_oversize_blob(self):
        self.changed(text='x'*200);r=module.audit(self.root,self.base,max_bytes=100);self.assertEqual(r['status'],'failed')
    def test_safe_symlink(self):
        (self.root/'link').symlink_to('README.md');self.commit();self.assertEqual(module.audit(self.root,self.base)['status'],'passed')
    def test_escaping_symlink(self):
        (self.root/'link').symlink_to('../secret');self.commit();self.assertEqual(module.audit(self.root,self.base)['status'],'failed')
    def test_spaces_and_unicode(self): self.assertEqual(self.changed('folder/a space-é.txt')['status'],'passed')
    def test_hash_is_stable(self):
        self.changed();a=module.audit(self.root,self.base);b=module.audit(self.root,self.base);self.assertEqual(a['checked_manifest_sha256'],b['checked_manifest_sha256'])
    def test_subprocess_failure_is_not_pass(self):
        with self.assertRaises(ValueError):module.audit(self.root/'missing')

if __name__=='__main__':unittest.main()
