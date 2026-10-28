import io
import json
import subprocess
import tarfile
import zlib

from leakguard.rules import b62


def gh_token(prefix="ghp", body="a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5"):
    return f"{prefix}_{body}{b62(zlib.crc32(body.encode())).rjust(6, '0')}"


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), "-c", "user.name=T", "-c", "user.email=t@t", *args], check=True, capture_output=True)


def tar_bytes(files, gz=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for name, data in files.items():
            if isinstance(data, str):
                data = data.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def make_image(path, layers, env=(), history=(), gz=False):
    names = [f"layer{i}/layer.tar" for i in range(len(layers))]
    config = {"config": {"Env": list(env)}, "history": [{"created_by": h} for h in history]}
    files = {"manifest.json": json.dumps([{"Config": "cfg.json", "Layers": names}]), "cfg.json": json.dumps(config)}
    for n, l in zip(names, layers):
        files[n] = tar_bytes(l, gz)
    path.write_bytes(tar_bytes(files))
