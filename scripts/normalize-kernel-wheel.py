"""Canonicalize the container ZIP while preserving every wheel payload byte."""

from io import BytesIO
from pathlib import Path, PurePosixPath
import sys
from zipfile import ZIP_STORED, ZipFile, ZipInfo


def normalize(path: Path) -> None:
    output = BytesIO()
    with ZipFile(path) as original, ZipFile(output, "w", compression=ZIP_STORED) as canonical:
        names = original.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate wheel members")
        for name in sorted(names):
            member = PurePosixPath(name)
            if member.is_absolute() or ".." in member.parts or "\\" in name or name.endswith("/"):
                raise ValueError("unexpected wheel member")
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            canonical.writestr(entry, original.read(name))
    path.write_bytes(output.getvalue())


if __name__ == "__main__":
    normalize(Path(sys.argv[1]))
