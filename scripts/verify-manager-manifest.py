#!/usr/bin/env python3
"""Verify manager OCI platforms, child images, labels, and provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any


REQUIRED_PLATFORMS = {("linux", "amd64"), ("linux", "arm64")}
IMAGE_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}
INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}
DIGEST_PATTERN = re.compile(r"^sha256:([0-9a-f]{64})$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    oci = subparsers.add_parser("oci", help="verify a local OCI archive")
    oci.add_argument("archive", type=Path)
    oci.add_argument("--revision", required=True)

    registry = subparsers.add_parser(
        "registry", help="verify registry index and Buildx image metadata"
    )
    registry.add_argument("manifest", type=Path, help="raw OCI index JSON")
    registry.add_argument("--images", type=Path, required=True)
    registry.add_argument("--revision", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return document


def descriptor_digest(descriptor: dict[str, Any], context: str) -> str:
    digest = descriptor.get("digest")
    match = DIGEST_PATTERN.fullmatch(digest) if isinstance(digest, str) else None
    if match is None:
        raise SystemExit(f"{context}: invalid sha256 digest {digest!r}")
    size = descriptor.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise SystemExit(f"{context}: invalid descriptor size {size!r}")
    return match.group(1)


def required_descriptors(index: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise SystemExit("manager manifest: 'manifests' must be an array")

    required: dict[tuple[str, str], dict[str, Any]] = {}
    for position, descriptor in enumerate(manifests):
        if not isinstance(descriptor, dict):
            raise SystemExit(f"manager manifest descriptor {position}: expected an object")
        platform = descriptor.get("platform", {})
        if not isinstance(platform, dict):
            raise SystemExit(f"manager manifest descriptor {position}: invalid platform")
        key = (platform.get("os"), platform.get("architecture"))
        if key not in REQUIRED_PLATFORMS:
            continue
        context = f"manager manifest {key[0]}/{key[1]}"
        if descriptor.get("mediaType") not in IMAGE_MEDIA_TYPES:
            raise SystemExit(f"{context}: descriptor is not an image manifest")
        descriptor_digest(descriptor, context)
        if key in required:
            raise SystemExit(f"{context}: duplicate platform descriptor")
        required[key] = descriptor

    missing = sorted(REQUIRED_PLATFORMS - required.keys())
    if missing:
        rendered = ", ".join(f"{os_name}/{arch}" for os_name, arch in missing)
        raise SystemExit(f"manager manifest missing required platform(s): {rendered}")
    digests = {descriptor["digest"] for descriptor in required.values()}
    if len(digests) != len(REQUIRED_PLATFORMS):
        raise SystemExit("manager manifest required platforms must use distinct images")
    return required


def validate_image_config(
    document: dict[str, Any], platform: tuple[str, str], revision: str
) -> None:
    context = f"manager image {platform[0]}/{platform[1]}"
    observed = (document.get("os"), document.get("architecture"))
    if observed != platform:
        raise SystemExit(f"{context}: config architecture is {observed!r}")
    config = document.get("config")
    if not isinstance(config, dict):
        raise SystemExit(f"{context}: missing image config")
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        raise SystemExit(f"{context}: missing OCI labels")
    required = {
        "org.opencontainers.image.revision": revision,
        "io.leash.manager.contract.version": "1",
        "io.leash.manager.contract.min-compatible": "1",
    }
    for key, expected in required.items():
        if labels.get(key) != expected:
            raise SystemExit(
                f"{context}: label {key}: {labels.get(key)!r} != {expected!r}"
            )


def validate_registry(
    index: dict[str, Any], images: dict[str, Any], revision: str
) -> None:
    required_descriptors(index)
    by_platform: dict[tuple[str, str], dict[str, Any]] = {}
    for key, document in images.items():
        if not isinstance(document, dict):
            raise SystemExit(f"manager registry image {key!r}: expected an object")
        platform = (document.get("os"), document.get("architecture"))
        if platform in REQUIRED_PLATFORMS:
            if platform in by_platform:
                raise SystemExit(
                    f"manager registry metadata duplicates {platform[0]}/{platform[1]}"
                )
            by_platform[platform] = document
    missing = sorted(REQUIRED_PLATFORMS - by_platform.keys())
    if missing:
        rendered = ", ".join(f"{os_name}/{arch}" for os_name, arch in missing)
        raise SystemExit(f"manager registry metadata missing platform(s): {rendered}")
    for platform, document in by_platform.items():
        validate_image_config(document, platform, revision)


def read_oci_blob(archive: tarfile.TarFile, digest: str, expected_size: int) -> bytes:
    match = DIGEST_PATTERN.fullmatch(digest)
    if match is None:
        raise SystemExit(f"OCI archive: invalid blob digest {digest!r}")
    name = f"blobs/sha256/{match.group(1)}"
    try:
        member = archive.getmember(name)
    except KeyError as error:
        raise SystemExit(f"OCI archive: missing {name}") from error
    if member.size != expected_size:
        raise SystemExit(
            f"OCI archive: {name} size {member.size} != descriptor {expected_size}"
        )
    handle = archive.extractfile(member)
    if handle is None:
        raise SystemExit(f"OCI archive: cannot read {name}")
    content = handle.read()
    observed = hashlib.sha256(content).hexdigest()
    if observed != match.group(1):
        raise SystemExit(f"OCI archive: digest mismatch for {name}")
    return content


def decode_json(content: bytes, context: str) -> dict[str, Any]:
    document = json.loads(content)
    if not isinstance(document, dict):
        raise SystemExit(f"{context}: expected a JSON object")
    return document


def validate_oci(archive_path: Path, revision: str) -> None:
    with tarfile.open(archive_path) as archive:
        index_handle = archive.extractfile("index.json")
        if index_handle is None:
            raise SystemExit("OCI archive: missing index.json")
        outer = decode_json(index_handle.read(), "OCI index")
        outer_manifests = outer.get("manifests")
        if not isinstance(outer_manifests, list):
            raise SystemExit("OCI index: 'manifests' must be an array")

        if any(
            isinstance(item, dict) and item.get("platform")
            for item in outer_manifests
        ):
            platform_index = outer
        else:
            indexes = [
                item
                for item in outer_manifests
                if isinstance(item, dict) and item.get("mediaType") in INDEX_MEDIA_TYPES
            ]
            if len(indexes) != 1:
                raise SystemExit("OCI archive: expected one platform index")
            descriptor = indexes[0]
            digest = descriptor_digest(descriptor, "OCI platform index")
            platform_index = decode_json(
                read_oci_blob(archive, f"sha256:{digest}", descriptor["size"]),
                "OCI platform index",
            )

        for platform, descriptor in required_descriptors(platform_index).items():
            manifest_digest = descriptor_digest(
                descriptor, f"OCI image {platform[0]}/{platform[1]}"
            )
            manifest = decode_json(
                read_oci_blob(
                    archive, f"sha256:{manifest_digest}", descriptor["size"]
                ),
                f"OCI image manifest {platform[0]}/{platform[1]}",
            )
            config_descriptor = manifest.get("config")
            if not isinstance(config_descriptor, dict):
                raise SystemExit(
                    f"OCI image {platform[0]}/{platform[1]}: missing config descriptor"
                )
            if config_descriptor.get("mediaType") not in CONFIG_MEDIA_TYPES:
                raise SystemExit(
                    f"OCI image {platform[0]}/{platform[1]}: invalid config media type"
                )
            config_digest = descriptor_digest(
                config_descriptor, f"OCI config {platform[0]}/{platform[1]}"
            )
            config = decode_json(
                read_oci_blob(
                    archive, f"sha256:{config_digest}", config_descriptor["size"]
                ),
                f"OCI image config {platform[0]}/{platform[1]}",
            )
            validate_image_config(config, platform, revision)


def main() -> int:
    args = parse_args()
    if args.mode == "oci":
        validate_oci(args.archive, args.revision)
    else:
        validate_registry(
            load_json(args.manifest), load_json(args.images), args.revision
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
