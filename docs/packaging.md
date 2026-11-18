# Packaging: verifying an rpm change

The `.deb` and `.rpm` are built by `make release` (CLAUDE.md §8). The rpm
traps worth knowing (bare `%macro` in a spec comment, a hand-dated top
`%changelog` entry) are in CLAUDE.md §5 and enforced by
`scripts/tests/check_rpm_spec_macros.sh`. Both only show on an EL build host:
Debian/Ubuntu rpm ships no `redhat/macros`, so a parse on the dev box or in CI
(Ubuntu runners) passes. Verify a packaging change in an EL container.

## Parse only

Catches the macro-in-comment class and needs no staged tree:

```bash
docker run --rm --network host -v "$PWD":/src:ro almalinux:8 sh -c \
  'dnf -y -q install rpm-build && rpmspec -P \
     --define "pkgroot /tmp/pk" --define "projectroot /src" \
     /src/packaging/rpm/SPECS/cfm.spec >/dev/null'
```

## Full build

Also verifies `%files` and `%post`, but needs a staged tree: `%install` copies
from `%{pkgroot}` and skips silently when it is absent, so an unstaged run dies
in `%files` with a misleading "File not found".

```bash
make stage-rpm            # populates build/pkgroot
docker run --rm --network host -v "$PWD":/src:ro almalinux:8 sh -c \
  'dnf -y -q install rpm-build && mkdir -p /rt/BUILDROOT && rpmbuild \
     --define "_topdir /rt" --define "debug_package %{nil}" \
     --define "pkgroot /src/build/pkgroot" --define "projectroot /src" \
     --buildroot /rt/BUILDROOT --target x86_64 \
     -bb /src/packaging/rpm/SPECS/cfm.spec'
```

This recipe bypasses the Makefile, so on EL10 it still clamps today's files to
00:00 UTC. To check the `%changelog` date / `SOURCE_DATE_EPOCH` handling for
real, build `bin/cfm` on the host first and run `make -o build rpm` inside
`almalinux:10`.
