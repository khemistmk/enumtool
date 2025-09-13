import sys
import importlib
import compileall

MODULES = [
    'enumtool',
    'enumtool.scan',
    'enumtool.tor_utils',
    'enumtool.ports',
    'enumtool.http_fingerprint',
    'enumtool.dns_utils',
    'enumtool.passive_sources',
]

def main() -> int:
    ok = True
    print(f"Python: {sys.version}")
    for m in MODULES:
        try:
            importlib.import_module(m)
            print(f"OK import {m}")
        except Exception as e:
            print(f"FAIL import {m}: {e}")
            ok = False
    c = compileall.compile_dir('src', quiet=1)
    print('compileall:', 'OK' if c else 'FAIL')
    return 0 if ok and c else 1

if __name__ == '__main__':
    raise SystemExit(main())
