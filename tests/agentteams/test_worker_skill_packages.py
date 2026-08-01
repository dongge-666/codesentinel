from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from codesentinel.agentteams.role_models import ROLE_PAYLOAD_MODELS, ROLE_SCHEMA_NAMES
from codesentinel.agentteams.serialization import canonical_json_bytes, sha256_hex

REPOSITORY = Path(__file__).parents[2]
SKILLS_ROOT = REPOSITORY / "deploy" / "agentteams" / "worker-skills"

EXPECTED = {
    "codesentinel-diff-review": {
        "worker": "cs-diff-analyzer",
        "role": "diff_analyzer",
        "prompt": "diff-analyzer-1.0.0",
    },
    "codesentinel-security-review": {
        "worker": "cs-security-scanner",
        "role": "security_scanner",
        "prompt": "security-semantic-1.0.0",
    },
    "codesentinel-quality-review": {
        "worker": "cs-quality-reviewer",
        "role": "quality_reviewer",
        "prompt": "quality-review-1.0.0",
    },
}


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def front_matter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "---"
    end = lines.index("---", 1)
    values = {}
    for line in lines[1:end]:
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def test_exactly_three_role_isolated_skill_packages() -> None:
    directories = {path.name for path in SKILLS_ROOT.iterdir() if path.is_dir()}
    assert directories == set(EXPECTED)
    seen_workers = set()
    seen_roles = set()

    for skill_name, expected in EXPECTED.items():
        root = SKILLS_ROOT / skill_name
        relative_files = {
            path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
        }
        assert relative_files == {
            "SKILL.md",
            "deployment-manifest.template.json",
            "references/example-payload.json",
            "references/input-contract.md",
            "references/payload.schema.json",
            "scripts/build-delivery.sh",
            "scripts/verify-runtime-binding.py",
            "skill-manifest.json",
        }
        assert not (root / "deployment-manifest.json").exists()

        metadata = front_matter(root / "SKILL.md")
        assert metadata["name"] == skill_name
        assert metadata["description"]
        assert expected["worker"] in metadata["assign_when"]

        manifest = read_json(root / "skill-manifest.json")
        assert manifest["skill_name"] == skill_name
        assert manifest["worker_name"] == expected["worker"]
        assert manifest["role"] == expected["role"]
        assert manifest["prompt_version"] == expected["prompt"]
        assert manifest["payload_schema"] == (
            f"{ROLE_SCHEMA_NAMES[expected['role']]}@1.0.0"
        )
        assert manifest["required_source_dirty"] is False
        assert manifest["deployment_binding"] == "deployment-manifest.json"
        seen_workers.add(manifest["worker_name"])
        seen_roles.add(manifest["role"])

    assert len(seen_workers) == 3
    assert len(seen_roles) == 3


def test_examples_match_shared_runtime_contracts_and_reference_schemas() -> None:
    for skill_name, expected in EXPECTED.items():
        root = SKILLS_ROOT / skill_name
        role = expected["role"]
        example = read_json(root / "references" / "example-payload.json")
        model = ROLE_PAYLOAD_MODELS[role]
        validated = model.model_validate_json(canonical_json_bytes(example))
        assert validated.model_dump(mode="json") == example

        reference_schema = read_json(root / "references" / "payload.schema.json")
        generated_schema = model.model_json_schema()
        assert reference_schema["title"] == f"{ROLE_SCHEMA_NAMES[role]}@1.0.0"
        assert reference_schema["additionalProperties"] is False
        assert set(reference_schema["properties"]) == set(generated_schema["properties"])
        assert set(reference_schema["required"]) == set(generated_schema["required"])
        if role != "diff_analyzer":
            draft_name = (
                "SecurityFindingDraft"
                if role == "security_scanner"
                else "QualityFindingDraft"
            )
            reference_draft = reference_schema["properties"]["findings"]["items"]
            generated_draft = generated_schema["$defs"][draft_name]
            assert reference_draft["additionalProperties"] is False
            assert set(reference_draft["properties"]) == set(
                generated_draft["properties"]
            )
            assert set(reference_draft["required"]) == set(generated_draft["required"])
            for field in ("category", "severity"):
                assert reference_draft["properties"][field]["enum"] == (
                    generated_draft["properties"][field]["enum"]
                )


def test_deployment_templates_require_clean_materialization() -> None:
    template_hashes = set()
    for skill_name in EXPECTED:
        template = read_json(
            SKILLS_ROOT / skill_name / "deployment-manifest.template.json"
        )
        assert template["skill_name"] == skill_name
        assert template["source_revision"] == "__P10_3A_COMMIT__"
        assert template["source_dirty"] is False
        assert template["runtime_bundle_ref"] == "__SHARED_RUNTIME_BUNDLE_REF__"
        assert template["runtime_bundle_sha256"] == "__RUNTIME_BUNDLE_SHA256__"
        template_hashes.add(sha256_hex(canonical_json_bytes(template)))
    assert len(template_hashes) == 3


def test_skill_scripts_are_identical_lf_only_and_verify_before_execution() -> None:
    scripts = []
    verifiers = []
    for skill_name in EXPECTED:
        scripts_root = SKILLS_ROOT / skill_name / "scripts"
        content = (scripts_root / "build-delivery.sh").read_bytes()
        scripts.append(content)
        verifiers.append((scripts_root / "verify-runtime-binding.py").read_bytes())
        assert content.startswith(b"#!/usr/bin/env bash\nset -euo pipefail\n")
        assert b"\r\n" not in content
        assert b"deployment-manifest.json" in content
        assert b"verify-runtime-binding.py" in content
        assert b"expected_sha256" not in content
        assert b"python \"$runtime_bundle\" \"$@\"" in content
    assert len(set(scripts)) == 1
    assert len(set(verifiers)) == 1


def test_runtime_verifier_binds_clean_internal_and_external_manifests(
    tmp_path: Path,
) -> None:
    source_revision = "a" * 40
    archive_name = "codesentinel-agentteams-runtime-0.1.0.pyz"
    runtime = tmp_path / archive_name
    internal = {
        "bundle_version": "0.1.0",
        "contract_version": "1.0.0",
        "source_revision": source_revision,
        "source_dirty": False,
    }
    with zipfile.ZipFile(runtime, mode="w") as archive:
        archive.writestr(
            "codesentinel/agentteams/runtime-manifest.json",
            canonical_json_bytes(internal),
        )
    runtime_sha256 = hashlib.sha256(runtime.read_bytes()).hexdigest()
    skill_name = "codesentinel-security-review"
    verifier = SKILLS_ROOT / skill_name / "scripts" / "verify-runtime-binding.py"
    deployment = {
        "schema_name": "CodeSentinelWorkerSkillDeployment",
        "schema_version": "1.0.0",
        "skill_name": skill_name,
        "skill_version": "1.0.0",
        "source_revision": source_revision,
        "source_dirty": False,
        "runtime_bundle_ref": f"shared/projects/codesentinel/runtime/{archive_name}",
        "runtime_bundle_sha256": runtime_sha256,
    }
    manifest = tmp_path / "deployment-manifest.json"
    manifest.write_bytes(canonical_json_bytes(deployment))

    accepted = subprocess.run(
        [sys.executable, str(verifier), str(manifest), str(runtime), skill_name],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert accepted.returncode == 0
    assert accepted.stdout.strip() == "runtime binding verified"

    deployment["runtime_bundle_sha256"] = "0" * 64
    manifest.write_bytes(canonical_json_bytes(deployment))
    rejected = subprocess.run(
        [sys.executable, str(verifier), str(manifest), str(runtime), skill_name],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert rejected.returncode == 2
    assert rejected.stderr.strip() == "runtime binding verification failed"

    deployment["runtime_bundle_sha256"] = runtime_sha256
    deployment["source_revision"] = "__P10_3A_COMMIT__"
    manifest.write_bytes(canonical_json_bytes(deployment))
    placeholder = subprocess.run(
        [sys.executable, str(verifier), str(manifest), str(runtime), skill_name],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert placeholder.returncode == 2


def test_skill_sources_contain_no_bound_runtime_or_secret_value() -> None:
    all_files = [path for path in SKILLS_ROOT.rglob("*") if path.is_file()]
    combined = b"\n".join(path.read_bytes() for path in all_files)
    for forbidden in (
        b"sk-",
        b"Bearer ",
        b"api_key=",
        b"D:\\\\",
        b"C:\\\\",
    ):
        assert forbidden not in combined
