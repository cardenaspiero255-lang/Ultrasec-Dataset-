#!/usr/bin/env python3
"""Native installed PyMdown Markdown extension; private corpus is never touched."""
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import markdown
from pymdownx.snippets import SnippetMissingError

if len(sys.argv)!=2 or sys.argv[1] not in {'VULNERABLE','PATCHED'}:
    raise SystemExit('Expected VULNERABLE or PATCHED')
variant=sys.argv[1]
def render(doc,base):
    return markdown.markdown(doc,extensions=['pymdownx.snippets'],extension_configs={'pymdownx.snippets':{'base_path':[str(base)],'restrict_base_path':True}})
with TemporaryDirectory(prefix='ultrasec-native-pymdown-') as td:
    root=Path(td);docs=root/'docs';sibling=root/'docs_private'
    docs.mkdir();sibling.mkdir()
    (docs/'safe.txt').write_text('ALLOWED_MARKER_52E5',encoding='utf-8')
    (sibling/'private.txt').write_text('SIBLING_MARKER_66F2',encoding='utf-8')
    assert 'ALLOWED_MARKER_52E5' in render('---8<--- "safe.txt"',docs)
    exposed=False
    try:
        x=render('---8<--- "../docs_private/private.txt"',docs)
        exposed='SIBLING_MARKER_66F2' in x
    except SnippetMissingError:
        exposed=False
    expected=variant=='VULNERABLE'
    if exposed!=expected: raise SystemExit(f'FAIL-CLOSED expected {expected}, got {exposed}')
    print(json.dumps({'project':'facelessuser/pymdown-extensions','variant':variant,'legitimate_allowed':True,'sibling_prefix_exposed':exposed,'oracle':'EXPECTED_RED' if expected else 'EXPECTED_GREEN','scope':'native installed full Markdown extension'}))
