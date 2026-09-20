from __future__ import annotations

import io
import zipfile
from pathlib import Path


def pack_folder(folder: str | Path, progress=None) -> bytes:
    root = Path(folder)
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for index, path in enumerate(files):
            archive.write(path, path.relative_to(root).as_posix())
            if progress:
                progress(int((index + 1) * 100 / max(1, len(files))))
    return stream.getvalue()


def unpack_folder(data: bytes, destination: str | Path) -> None:
    root = Path(destination).resolve()
    with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
        infos = archive.infolist()
        if len(infos) > 100_000:
            raise ValueError("Archive contains too many entries")
        if sum(info.file_size for info in infos) > 10 * 1024 * 1024 * 1024:
            raise ValueError("Archive expands beyond the 10 GiB safety limit")
        for info in infos:
            target = (root / info.filename).resolve()
            if root != target and root not in target.parents:
                raise ValueError("Unsafe archive path detected")
        archive.extractall(root)
