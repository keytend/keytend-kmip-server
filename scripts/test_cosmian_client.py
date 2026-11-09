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

"""Unmodified released Cosmian RequestMessage probe; one owned native HTTPS fixture.

The released SDK owns serialization, verified mTLS transport and response
decoding. One SDK process runs the planned lifecycle (each step a separate
RequestMessage, continuing only with SDK-decoded identifiers); further processes
run the transport/policy negatives, each followed by an authorized Create.
SDK print_json logs are inspected only after the processes exit, to attribute a
decode failure to the server or the SDK; nothing is translated or fed back.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

from image_evidence import source_commit
from test_runtime import ROOT, Server, free_port

PIN = json.loads((ROOT / "interop/cosmian/release.json").read_text())
CARGO = ROOT / ".cache/cosmian-cargo"
TARGET = ROOT / ".cache/cosmian-target"


def sha(path):
    with pathlib.Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sdk_evidence():
    lock = tomllib.loads((ROOT / "interop/cosmian/Cargo.lock").read_text())
    evidence = {}
    # Check every pinned archive; additionally compare all released files of the
    # client, model and two companion KMS libraries to the actual compiled source.
    for package in lock["package"]:
        if "checksum" not in package:
            continue
        name, version = package["name"], package["version"]
        stem = name + "-" + version
        archives = list((CARGO / "registry/cache").glob("*/" + stem + ".crate"))
        if len(archives) != 1 or sha(archives[0]) != package["checksum"]:
            raise ValueError("pinned archive missing or changed: " + stem)
        if name not in PIN["kms_crates"]:
            continue
        if version != PIN["version"] or package["checksum"] != PIN["kms_crates"][name]:
            raise ValueError("unexpected KMS dependency release: " + stem)
        roots = list((CARGO / "registry/src").glob("*/" + stem))
        if len(roots) != 1:
            raise ValueError("expected one SDK extraction: " + stem)
        files = {}
        with tarfile.open(archives[0]) as archive:
            for member in archive.getmembers():
                if member.isfile():
                    relative = str(pathlib.PurePosixPath(member.name).relative_to(stem))
                    digest = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                    if sha(roots[0] / relative) != digest:
                        raise ValueError("released SDK file modified: " + relative)
                    files[relative] = digest
        vcs = json.loads((roots[0] / ".cargo_vcs_info.json").read_text())
        if vcs["git"]["sha1"] != PIN["commit"]:
            raise ValueError("unexpected release source commit")
        evidence[name] = dict(archive_sha256=package["checksum"], released_files=len(files),
                              released_tree_sha256=hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest())
    if set(evidence) != set(PIN["kms_crates"]):
        raise ValueError("missing SDK companion source")
    return dict(kms_crates=evidence, registry_archives_verified=sum("checksum" in p for p in lock["package"]))



REGISTRY = json.loads((ROOT / "src/wire_registry.json").read_text())["2.1"]
# The SDK's Rust enum type -> the KMIP 2.1 enumeration table (section 11).
SDK_TABLES = {"ErrorReason": "ResultReason", "HashingAlgorithm": "HashingAlgorithm"}
NAME_ERROR = re.compile(r'invalid value: string "(\w+)", expected valid (\w+) name')
LIFECYCLE = ["create", "activate", "get-exact", "get-attributes", "get-all-attributes", "encrypt", "decrypt",
             "kat-encrypt", "kat-decrypt", "other-owner-get", "revoke", "destroy", "get-after-destroy", "get-missing"]
# Expected decoded refusals: 2.1 Table 222 (Get) lists Object Not Found, the
# server reports another owner's object as missing and answers Object Destroyed
# for the owner's destroyed object (docs/interpretations.md#result-reasons).
REFUSALS = {"other-owner-get": "ObjectNotFound", "get-after-destroy": "ObjectDestroyed", "get-missing": "ObjectNotFound"}


def sdk_log(path):
    """SDK events and every received-TTLV diagnostic, in order; never fed back."""
    log = path.read_text()
    events = [json.loads(line) for line in log.splitlines() if line.startswith('{"') and '"event":' in line]
    results = [e for e in events if e.get("event") == "sdk_result"]
    if len(results) != 1:
        raise ValueError("expected one SDK result event")
    # print_json is the SDK's own public diagnostic option. Its received TTLV is
    # offline evidence only. No UID or payload is used to continue a lifecycle.
    marker = "KMIP Response <==\n"
    observations = [json.JSONDecoder().raw_decode(part)[0] for part in log.split(marker)[1:]]
    return [e for e in events if e.get("event") == "step"], results[0], observations


def tag_is(node, name, number):
    return node["tag"] in (name, number)


def observed_result(observation):
    """Result Status and Reason of a received response, by name or hex."""
    if not tag_is(observation, "ResponseMessage", "0x42007b"):
        raise ValueError("unexpected observed response tag")
    items = [n for n in observation["value"] if tag_is(n, "BatchItem", "0x42000f")]
    if len(items) != 1:
        raise ValueError("expected one observed response batch")
    fields = {n["tag"]: n["value"] for n in items[0]["value"]}
    status = fields.get("ResultStatus", fields.get("0x42007f"))
    reason = fields.get("ResultReason", fields.get("0x42007e"))
    return enum_name("ResultStatus", status), enum_name("ResultReason", reason)


def enum_name(table, value):
    """The 2.1 normalized name of an enumeration written as a name, hex or a
    Number (Profiles 2.1 section 5.5.1.6.7; the server's JSON enumeration form
    is configurable, docs/interpretations.md). Values without a 2.1 name stay as written."""
    if isinstance(value, str) and value.startswith("0x"):
        value = int(value, 16)
    if isinstance(value, int):
        names = [name for name, number in REGISTRY["enums"].get(table, {}).items() if number == value]
        return names[0] if len(names) == 1 else value
    return value


def normative(table, name):
    """Whether `name` is the KMIP 2.1 normalized text (Profiles 2.1 section
    5.4.1.1) of a value of `table`, as generated from the pinned specification."""
    return name in REGISTRY["enums"].get(table, {})


def attribute(error, observation):
    """Attribute an SDK decode error after the fact, from the SDK's own log."""
    match = NAME_ERROR.search(error)
    if match and observation is not None:
        name, sdk_type = match.groups()
        table = SDK_TABLES.get(sdk_type)
        if table and normative(table, name) and name in json.dumps(observation):
            return dict(attribution="sdk", finding="sdk_rejects_normative_enumeration_name",
                        name=name, sdk_type=sdk_type, kmip_table=table,
                        clause="Profiles 2.1 sections 5.4.1.1 (normalization) and 5.5.1.6.7 (JSON Enumeration text)")
    return dict(attribution="unattributed", finding="unexplained_sdk_error")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True, help="native server copy under artifacts/")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.run_id):
        raise ValueError("run-id must be a simple directory name")
    # Reject a caller accidentally pointing back into another checkout.
    args.binary.resolve().relative_to(ROOT / "artifacts")
    output = ROOT / "artifacts/cosmian-client" / args.run_id
    output.mkdir(parents=True, exist_ok=False)
    binary_sha256 = sha(args.binary)
    env = dict(os.environ, CARGO_HOME=str(CARGO), CARGO_TARGET_DIR=str(TARGET))
    # No root/server manifest is ever passed to Cargo.
    with (output / "client-fetch.log").open("w") as log:
        subprocess.run(["cargo", "fetch", "--locked", "--manifest-path", str(ROOT / "interop/cosmian/Cargo.toml")],
                       env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    with (output / "client-build.log").open("w") as log:
        subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(ROOT / "interop/cosmian/Cargo.toml"), "-j", "2"],
                       env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    sdk = sdk_evidence()
    adapter = TARGET / "debug/keytend-kmip-server-cosmian-interop"
    report = dict(status="running", starting_head=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        scope="released SDK RequestMessage HTTPS JSON TTLV 2.1 lifecycle trial, non-production only",
        runtime_binary_sha256=binary_sha256, source_commit=source_commit()[0],
        image_execution_credit=False, sdk=sdk, adapter_binary_sha256=sha(adapter), client_build_log_sha256=sha(output / "client-build.log"),
        rustc=subprocess.check_output(["rustc", "--version"], text=True).strip(), probes=[],
        cleanup={})
    result_path = output / "report.json"
    result_path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        with tempfile.TemporaryDirectory(prefix="owned-fixture-", dir=output) as directory:
            server = Server(directory, binary=args.binary.resolve())
            https = free_port()
            # Issue DNS-only localhost cert so wrong-host uses the same listener,
            # endpoint and chain with an IP name that is absent from the SAN.
            (server.pki / "dns-only.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
            subprocess.run(["openssl", "x509", "-req", "-in", str(server.pki / "server.csr"), "-CA", str(server.pki / "ca.pem"),
                "-CAkey", str(server.pki / "ca.key"), "-CAcreateserial", "-out", str(server.pki / "server.pem"),
                "-days", "1", "-extfile", str(server.pki / "dns-only.ext")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for name in ["wrong-ca", "untrusted"]:
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(server.pki / (name + ".key")),
                    "-out", str(server.pki / (name + ".pem")), "-days", "1", "-subj", "/CN=" + name],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "verify", "-CAfile", str(server.pki / "ca.pem"),
                *[str(server.pki / (name + ".pem")) for name in ["client", "other", "unlisted"]]],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Record public certificate fingerprints/configuration, never key bytes.
            report["fixture"] = dict(ttlv_port=server.port, https_port=https, health_port=server.health,
                server_san="DNS:localhost", negative_hostname="127.0.0.1", accept_invalid_certs=False,
                certificate_sha256={name: sha(server.pki / (name + ".pem")) for name in ["ca", "server", "client", "other", "unlisted", "wrong-ca", "untrusted"]},
                policy_sha256=sha(server.pki / "policy.json"))
            try:
                previous = os.environ.get("KMIP_HTTPS_LISTEN")
                os.environ["KMIP_HTTPS_LISTEN"] = f"127.0.0.1:{https}"
                try:
                    server.start()
                finally:
                    if previous is None:
                        os.environ.pop("KMIP_HTTPS_LISTEN", None)
                    else:
                        os.environ["KMIP_HTTPS_LISTEN"] = previous
                report["owned_server_pid"] = server.process.pid
                modes = [("lifecycle", "lifecycle")]
                for negative in ["wrong-ca", "wrong-host", "no-identity", "untrusted", "unlisted", "other"]:
                    modes.extend([(negative, negative), ("after-" + negative, "authorized")])
                for label, mode in modes:
                    log = output / (label + ".log")
                    with log.open("w") as stream:
                        result = subprocess.run([str(adapter), str(server.pki), str(https), mode],
                            stdout=stream, stderr=subprocess.STDOUT, timeout=600)
                    steps, event, observations = sdk_log(log)
                    report["probes"].append(dict(label=label, exit_code=result.returncode, sdk_result=event, steps=steps,
                        sdk_received_ttlv_observations=observations, log=str(log.relative_to(ROOT)), log_sha256=sha(log)))
                    result_path.write_text(json.dumps(report, indent=2) + "\n")
                    print(label, "exit", result.returncode, event["status"], flush=True)
            finally:
                server.stop()
                report["cleanup"]["owned_server_exit_code"] = server.process.returncode if server.process else None
                report["cleanup"]["owned_server_stopped"] = server.process is not None and server.process.poll() is not None
                shutil.copyfile(pathlib.Path(directory) / "server.log", output / "server.log")
                report["server_log_sha256"] = sha(output / "server.log")
        report["cleanup"]["temporary_pki_and_store_removed"] = not pathlib.Path(directory).exists()
        # Assertions consume diagnostics only after all SDK processes have exited.
        summary = dict(passed=[], refused_as_expected=[], sdk_defects=[], server_defects=[], unattributed=[])
        for probe in report["probes"]:
            event, observations = probe["sdk_result"], probe["sdk_received_ttlv_observations"]
            if event["mode"] == "lifecycle":
                steps = probe["steps"]
                # Each step names its RequestMessage; the SDK logs one received
                # TTLV per exchange, in order.
                for step in steps:
                    name = step["step"]
                    if step["status"] == "passed":
                        summary["passed"].append(name)
                    elif step["status"] == "refused":
                        expected = REFUSALS.get(name)
                        reason = step["detail"]["result_reason"]
                        # The SDK's spelling of the same code (e.g. Object_Not_Found).
                        if expected and reason.replace("_", "") == expected:
                            summary["refused_as_expected"].append(name)
                        else:
                            summary["server_defects"].append(dict(step=name, detail=step["detail"]))
                    elif step["status"] == "sdk_error":
                        number = step["exchange"]
                        observation = observations[number - 1] if number <= len(observations) else None
                        finding = dict(step=name, error=step["detail"]["error"], **attribute(step["detail"]["error"], observation))
                        if observation is not None:
                            finding["observed_result"] = observed_result(observation)
                        expected = REFUSALS.get(name)
                        if expected:
                            finding["server_result_as_expected"] = finding.get("observed_result") == ("OperationFailed", expected)
                        summary["sdk_defects" if finding["attribution"] == "sdk" else "unattributed"].append(finding)
                    else:
                        summary["unattributed"].append(dict(step=name, status=step["status"], detail=step["detail"]))
                probe["exchanges"] = max(s["exchange"] for s in steps)
                if probe["exchanges"] != len(observations):
                    raise ValueError("SDK logged a different number of responses than exchanges")
                if set(LIFECYCLE) - {s["step"] for s in steps}:
                    raise ValueError("lifecycle did not reach every planned step")
            elif event["mode"] == "authorized":
                status, _ = observed_result(observations[0])
                if event["status"] != "decoded" or event["result_status"] != "Success" or status != "Success":
                    raise ValueError("authorized Create not decoded as Success: " + probe["label"])
                probe["finding"] = "decoded_create_success"
            elif event["mode"] in ("other", "unlisted"):
                # A CA-valid certificate without a policy entry gets the same
                # KMIP Permission Denied answer over HTTPS as over binary TLS.
                status, reason = observed_result(observations[0])
                if (status, reason) != ("OperationFailed", "PermissionDenied"):
                    raise ValueError(event["mode"] + " Create not refused with Permission Denied")
                if event["status"] == "decoded":
                    probe["finding"] = "decoded_permission_denied"
                else:
                    finding = dict(step=event["mode"] + "-principal-create", error=event["error"], **attribute(event["error"], observations[0]),
                                   observed_result=[status, reason], server_result_as_expected=True)
                    probe["finding"] = finding["finding"]
                    summary["sdk_defects" if finding["attribution"] == "sdk" else "unattributed"].append(finding)
            else:
                if not event["error_debug"].startswith("HttpClient(") or observations:
                    raise ValueError("negative did not fail in SDK transport")
                probe["finding"] = "transport_rejected"
        report["summary"] = summary
        report["postnegative_authorized_decoded_successes"] = sum(p.get("finding") == "decoded_create_success" for p in report["probes"])
        report["decoded_sdk_lifecycle_steps_passed"] = len(summary["passed"])
        report["status"] = "passed" if not (summary["sdk_defects"] or summary["server_defects"] or summary["unattributed"]) else \
            "partial_sdk_defects" if not (summary["server_defects"] or summary["unattributed"]) else "failed"
    except BaseException as error:
        report["status"] = "failed"
        report["harness_error"] = repr(error)
        raise
    finally:
        result_path.write_text(json.dumps(report, indent=2) + "\n")
        print(result_path, flush=True)
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
