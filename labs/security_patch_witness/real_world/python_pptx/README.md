# Reproduced python-pptx 1.0.2 expanded-package escape (upstream patch candidate)

This is a **real-library** application of the patch-witness workflow, for the already-public
[python-pptx issue #1137](https://github.com/scanny/python-pptx/issues/1137).
It does **not** claim an exploit through normal ZIP-based PowerPoint loading.

## Verified scope

The installed python-pptx 1.0.2 contains a directory-based package reader
(`_DirPkgReader`) whose membership and read methods operate directly on a path
built by joining the package root with a member name.

On an expanded package, `PackURI('/../outside.txt')` can read an adjacent
synthetic file. An in-package symlink can also point to an outside synthetic
file. Crucially, the public `Presentation(directory)` entry point will read
an outside XML part when the expanded package contains a symlink to it.
This is an observable file-read containment failure; it does not establish
that a normal ZIP .pptx file can cause the same escape.

## Proposed mitigation

[`directory-containment.patch`](directory-containment.patch) updates
`src/pptx/opc/serialized.py` to reject dot-segments and ensure real paths
remain inside the expanded-package root, consistently in membership checks
and reads. Legitimate nested parts and within-root symlinks continue to work.

[`test_serialized_security.py`](test_serialized_security.py) contains six
upstream-style pytest cases, including a public `Presentation(directory)`
regression, normal read preservation and a .pptx save/open round trip.

## Reproduction evidence

Tested locally with **python-pptx 1.0.2**, Linux, Python 3.13 and pytest 9:

- Original distribution: **4 failed, 2 passed**. The failures are precisely
  the four desired containment checks.
- Locally patched distribution: **6 passed**.
- Differential lab: three out-of-root reads succeed before, are blocked after,
  and succeed again after restoring the two original reader methods.
- End-to-end public `Presentation(directory)` symlink case behaves analogously.
- The ZIP writer was checked independently: writing an unsafe member name
  creates an entry in a ZIP file, but **did not overwrite a filesystem file**.
  Calling that direct operation an on-disk Zip-Slip exploit would be inaccurate.

## Reviewer notes / unresolved limits

This is a **candidate patch**, not an upstream fix, version release, security
advisory, or fully verified race-safe filesystem confinement solution.

The `realpath`/containment check and subsequent `open` are separate actions.
A concurrent attacker with write permissions on the expanded package can
potentially race symlink replacement between them. Addressing that threat
requires descriptor-relative path walking or an equivalent filesystem
primitive, with careful portability handling. Consider whether the
directory-tree trust boundary includes concurrent mutation before merging.

The regular upstream test suite has not been executed here. No third-party
repository files or customer data were written, and no untrusted executable
code was run in this demonstration. All observed outside files were disposable
synthetic fixtures.

**Upstream contribution:** This patch and test are supplied as reviewable
material. No upstream PR or security-fix deployment has occurred.
