#!/usr/bin/env python3
"""Offline regression tests for the standalone EKS kubeconfig script.

Checks node credential isolation, kubeconfig contents and permissions, explicit
recovery options, IMDS fallback, failure handling and node identity verification.
No AWS or Kubernetes endpoints are contacted; protocol tools use fixtures.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/get-aws-eks-token.sh'
MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from datetime import datetime, timedelta, timezone
name = os.path.basename(sys.argv[0])
a = sys.argv[1:]
mode = os.environ.get('FIXTURE_MODE', '')
expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
if name == 'curl':
    url = a[-1]
    assert '--noproxy' in a and '--max-time' in a and a[0] == '-q'
    if url.endswith('/api/token'):
        if mode == 'imdsv1': sys.exit(22)
        print('fake-imds-token')
    elif url.endswith('/document'): print(json.dumps({'instanceId': 'i-123abc', 'region': 'us-west-2'}))
    elif url.endswith('/security-credentials/'): print('node-role')
    else: print(json.dumps({'Code': 'Success', 'AccessKeyId': 'node-key', 'SecretAccessKey': 'node-secret', 'Token': 'node-session', 'Expiration': expiry}))
elif name == 'aws':
    assert os.environ['AWS_ACCESS_KEY_ID'] == 'node-key'
    assert os.environ['AWS_SECRET_ACCESS_KEY'] == 'node-secret'
    assert os.environ['AWS_SESSION_TOKEN'] == 'node-session'
    assert os.environ['AWS_CONFIG_FILE'] == '/dev/null'
    assert 'AWS_PROFILE' not in os.environ and 'AWS_ENDPOINT_URL' not in os.environ
    assert 'AWS_WEB_IDENTITY_TOKEN_FILE' not in os.environ
    if 'describe-instances' in a:
        assert a[a.index('--instance-ids') + 1] == 'i-123abc'
        if mode == 'ec2-denied': sys.exit(1)
        tags = [{'Key': 'aws:eks:cluster-name', 'Value': 'fixture'}]
        if mode == 'ambiguous': tags.append({'Key': 'kubernetes.io/cluster/other', 'Value': 'owned'})
        print(json.dumps({'Reservations': [{'Instances': [{'Tags': tags}]}]}))
    elif 'describe-cluster' in a:
        print(json.dumps({'cluster': {'endpoint': 'https://fixture.invalid', 'certificateAuthority': {'data': 'ZmFrZS1jYQ=='}}}))
    else:
        assert 'get-token' in a
        print(json.dumps({'status': {'token': 'k8s-aws-v1.fake', 'expirationTimestamp': expiry}}))
else:
    config = json.load(open(a[a.index('--kubeconfig') + 1]))
    assert config['users'][0]['user'] == {'token': 'k8s-aws-v1.fake'}
    user = 'some-user' if mode == 'wrong-identity' else 'system:node:fixture'
    print(json.dumps({'status': {'userInfo': {'username': user, 'groups': ['system:nodes']}}}))
'''


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('curl', 'aws', 'kubectl'):
            path = self.root / name
            path.write_text(MOCK)
            path.chmod(0o755)
        self.output = self.root / 'config'

    def run_script(self, *args, mode=''):
        env = dict(os.environ, PATH=f'{self.root}:{os.environ["PATH"]}',
                   AWS_ACCESS_KEY_ID='ambient-key', AWS_PROFILE='ambient-profile',
                   AWS_WEB_IDENTITY_TOKEN_FILE='/not-used', AWS_ENDPOINT_URL='https://not-used',
                   FIXTURE_MODE=mode)
        return subprocess.run([str(SCRIPT), '--output', str(self.output), *args],
                              env=env, text=True, capture_output=True)

    def test_generation_and_verification(self):
        result = self.run_script('--verify')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.output.read_text())
        self.assertEqual(config['clusters'][0]['cluster']['server'], 'https://fixture.invalid')
        self.assertEqual(config['users'][0]['user'], {'token': 'k8s-aws-v1.fake'})
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('node-secret', self.output.read_text() + result.stderr)
        self.assertNotIn('k8s-aws-v1.fake', result.stdout + result.stderr)
        self.assertIn('Verified identity: system:node:fixture', result.stderr)

    def test_failure_paths_publish_nothing(self):
        for mode in ('imdsv1', 'ec2-denied', 'ambiguous', 'wrong-identity'):
            with self.subTest(mode=mode):
                result = self.run_script('--verify', mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())

    def test_explicit_recovery(self):
        ca = self.root / 'ca.pem'
        ca.write_text('fake-ca')
        result = self.run_script('--cluster-name', 'fixture', '--server',
                                 'https://manual.invalid', '--ca-file', str(ca), mode='ec2-denied')
        self.assertEqual(result.returncode, 0, result.stderr)
        cluster = json.loads(self.output.read_text())['clusters'][0]['cluster']
        self.assertEqual(cluster['certificate-authority-data'], 'ZmFrZS1jYQ==')
        self.assertEqual(cluster['server'], 'https://manual.invalid')

    def test_explicit_imdsv1(self):
        result = self.run_script('--allow-imdsv1', mode='imdsv1')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_existing_file(self):
        self.output.write_text('keep me')
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.output.read_text(), 'keep me')


if __name__ == '__main__':
    unittest.main()
