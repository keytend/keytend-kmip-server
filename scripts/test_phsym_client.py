# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Released phsym SDK subset against exactly one owned native fixture.

Only the isolated Rust *client* manifest is built. Never invokes a server build.
Raw SDK sources, Cargo caches, PKI, store and binaries stay outside Git.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from image_evidence import source_commit
from test_runtime import ROOT, Server

PIN = json.loads((ROOT / "interop/phsym/release.json").read_text())
CACHE = ROOT / ".cache/sdk-research"
CARGO = ROOT / ".cache/phsym-cargo"
TARGET = ROOT / ".cache/phsym-target"


def sha(path):
    with pathlib.Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sdk_evidence():
    archive = CACHE / "phsym-v0.6.0.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(PIN["source_archive_url"], timeout=60) as response:
            archive.write_bytes(response.read())
    if sha(archive) != PIN["source_archive_sha256"]:
        raise ValueError("SDK release archive checksum mismatch")
    # Compare every release file against Cargo's actual pinned git checkout.
    candidates = list((CARGO / "git/checkouts").glob("kmip-rs-*/*/kmip/Cargo.toml"))
    roots = [p.parent.parent for p in candidates if subprocess.check_output(
        ["git", "-C", str(p.parent.parent), "rev-parse", "HEAD"], text=True
    ).strip() == PIN["commit"]]
    if len(roots) != 1:
        raise ValueError("expected one exact SDK source checkout")
    root = roots[0]
    files = {}
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            if member.isfile():
                name = str(pathlib.PurePosixPath(member.name).relative_to("kmip-rs-0.6.0"))
                digest = hashlib.sha256(source.extractfile(member).read()).hexdigest()
                if sha(root / name) != digest:
                    raise ValueError("SDK checkout differs from release: " + name)
                files[name] = digest
    if subprocess.check_output(["git", "-C", str(root), "diff", "HEAD", "--name-only"], text=True).strip():
        raise ValueError("SDK checkout modified")
    return dict(release=PIN, archive_path=str(archive.relative_to(ROOT)),
                release_file_count=len(files),
                release_tree_sha256=hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                license_sha256={name: files[name] for name in PIN["license_files"]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.run_id):
        raise ValueError("run-id must be a simple directory name")
    output = ROOT / "artifacts/phsym-client" / args.run_id
    output.mkdir(parents=True, exist_ok=False)
    CACHE.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_HOME=str(CARGO), CARGO_TARGET_DIR=str(TARGET))
    with (output / "client-build.log").open("w") as log:
        subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(ROOT / "interop/phsym/Cargo.toml"), "-j", "2"],
                       env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    sdk = sdk_evidence()
    adapter = TARGET / "debug/keytend-kmip-server-phsym-interop"
    report = dict(status="running", source_commit=source_commit()[0],
                  scope="released public Rust SDK on native mTLS binary TTLV 1.0-1.4; subset only; shared OVH maintainer",
                  runtime_binary_sha256=sha(args.binary),
                  image_execution_credit=False, sdk=sdk,
                  adapter_binary_sha256=sha(adapter),
                  rustc=subprocess.check_output(["rustc", "--version"], text=True).strip(),
                  client_build_log_sha256=sha(output / "client-build.log"), lanes=[])
    result_path = output / "report.json"
    result_path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        with tempfile.TemporaryDirectory(prefix="phsym-fixture-", dir=output) as directory:
            server = Server(directory, binary=args.binary.resolve())
            try:
                # Independently signed trust anchor and client; generated once, never committed.
                for name in ["wrong-ca", "untrusted"]:
                    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                    "-keyout", str(server.pki / (name + ".key")),
                                    "-out", str(server.pki / (name + ".pem")), "-days", "1", "-subj", "/CN=" + name],
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                server.start()
                report["owned_server_pid"] = server.process.pid
                for minor in range(5):
                    log = output / ("v1-" + str(minor) + ".log")
                    with log.open("w") as stream:
                        result = subprocess.run([str(adapter), str(server.pki), "127.0.0.1:" + str(server.port), str(minor)],
                                                stdout=stream, stderr=subprocess.STDOUT, timeout=120)
                    events = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
                    report["lanes"].append(dict(version="1." + str(minor), exit_code=result.returncode,
                                                checks=events, log=str(log.relative_to(ROOT)), log_sha256=sha(log)))
                    result_path.write_text(json.dumps(report, indent=2) + "\n")
                    print("KMIP 1." + str(minor), "exit", result.returncode, "checks", len(events), flush=True)
            finally:
                server.stop()
                report["owned_server_exit_code"] = server.process.returncode if server.process else None
                report["owned_server_stopped"] = server.process is not None and server.process.poll() is not None
                shutil.copyfile(pathlib.Path(directory) / "server.log", output / "server.log")
                report["server_log_sha256"] = sha(output / "server.log")
        report["temporary_pki_and_store_removed"] = not pathlib.Path(directory).exists()
        report["status"] = "passed_subset" if (len(report["lanes"]) == 5 and
            all(lane["exit_code"] == 0 for lane in report["lanes"]) and report["owned_server_stopped"]) else "failed"
        if report["status"] == "passed_subset" and any(event["status"].startswith("known_")
                for lane in report["lanes"] for event in lane["checks"]):
            report["status"] = "partial"
    except BaseException as error:
        report["status"] = "failed"
        report["harness_error"] = repr(error)
        raise
    finally:
        result_path.write_text(json.dumps(report, indent=2) + "\n")
        print(result_path, flush=True)
    if report["status"] != "passed_subset":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
