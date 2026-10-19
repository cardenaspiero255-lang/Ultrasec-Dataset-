"""Security regression for executing original SHA-pinned MISP function witnesses.

Existing public Semgrep CI RED: exec() in two original-code witness helpers.
Require function code object construction without direct exec/eval and reject
decorators before compiling original upstream function AST.
"""
from __future__ import annotations
import ast
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]/'verification'/'research'
FILES=[
 ROOT/'misp_original_evaluation_privacy.py',
 ROOT/'misp_original_evaluation_report_witness.py',
]


class MispOriginalHarnessSecurityTest(unittest.TestCase):
    def test_no_unrestricted_exec_or_eval_in_either_harness(self):
        for path in FILES:
            with self.subTest(path=path.name):
                tree=ast.parse(path.read_text(encoding='utf-8'))
                calls=[node.func.id for node in ast.walk(tree)
                       if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                       and node.func.id in {'exec','eval'}]
                self.assertEqual([],calls,'Direct dynamic execution must not bypass security scan')

    def test_loading_pinned_function_keeps_original_default_argument(self):
        for path in FILES:
            with self.subTest(path=path.name), tempfile.TemporaryDirectory() as d:
                spec=importlib.util.spec_from_file_location('safe_original_'+path.stem,path)
                module=importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                source='def original_case(x, actor=None):\\n    return (x, actor)\\n'
                # Literal newlines for a small trusted fixture, not arbitrary runtime source.
                source=source.replace('\\\\n','\\n')
                ns={}
                if hasattr(module,'_extract_original'):
                    f=Path(d)/'original.py'
                    f.write_text(source,encoding='utf-8')
                    module._extract_original(f,{'original_case'},ns)
                    function=ns['original_case']
                else:
                    function,_=module._original_function(source,'original_case',ns)
                self.assertEqual(function(123),(123,None))
                self.assertEqual(function(123,'owner'),(123,'owner'))

    def test_decorators_are_rejected_not_evaluated(self):
        for path in FILES:
            with self.subTest(path=path.name), tempfile.TemporaryDirectory() as d:
                spec=importlib.util.spec_from_file_location('safe_original_decorator_'+path.stem,path)
                module=importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                source='@unapproved_decorator\\ndef original_case(x):\\n    return x\\n'
                source=source.replace('\\\\n','\\n')
                ns={}
                with self.assertRaises(ValueError):
                    if hasattr(module,'_extract_original'):
                        f=Path(d)/'original.py'
                        f.write_text(source,encoding='utf-8')
                        module._extract_original(f,{'original_case'},ns)
                    else:
                        module._original_function(source,'original_case',ns)


if __name__=='__main__':
    unittest.main()
