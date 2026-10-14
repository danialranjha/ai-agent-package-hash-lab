"""Run actual-install tests and record their status; failures exit nonzero."""
import json
from pathlib import Path
import sys
import unittest
import experiment

suite = unittest.defaultTestLoader.discover('.', pattern='test_experiment.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
from test_experiment import IntegrityTests
experiment.save(IntegrityTests.result_data)
Path('artifacts/checks.json').write_text(json.dumps({
    'command': 'python3 validate.py', 'tests_run': result.testsRun,
    'failures': len(result.failures), 'errors': len(result.errors),
    'successful': result.wasSuccessful(),
    'scope': 'Tests rerun all nine real local pip installs, then check exact sink outcomes and containment.'
}, indent=2) + '\n')
sys.exit(0 if result.wasSuccessful() else 1)
