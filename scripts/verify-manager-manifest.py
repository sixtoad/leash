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
    oci.add_argument("--version", required=True)
    oci.add_argument("--channel", required=True)

    registry = subparsers.add_parser(
        "registry", help="verify registry index and Buildx image metadata"
    )
    registry.add_argument("manifest", type=Path, help="raw OCI index JSON")
    registry.add_argument("--image-amd64", type=Path, required=True)
    registry.add_argument("--image-arm64", type=Path, required=True)
    registry.add_argument("--revision", required=True)
    registry.add_argument("--digest", required=True)
    registry.add_argument("--version", required=True)
    registry.add_argument("--channel", required=True)

    descriptor = subparsers.add_parser(
        "descriptor", help="print one verified platform descriptor digest"
    )
    descriptor.add_argument("manifest", type=Path, help="raw OCI index JSON")
    descriptor.add_argument("--os", required=True)
    descriptor.add_argument("--arch", required=True)
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
    attestations: list[tuple[int, dict[str, Any]]] = []
    for position, descriptor in enumerate(manifests):
        if not isinstance(descriptor, dict):
            raise SystemExit(f"manager manifest descriptor {position}: expected an object")
        platform = descriptor.get("platform", {})
        if not isinstance(platform, dict):
            raise SystemExit(f"manager manifest descriptor {position}: invalid platform")
        key = (platform.get("os"), platform.get("architecture"))
        if key not in REQUIRED_PLATFORMS:
            if key == ("unknown", "unknown"):
                attestations.append((position, descriptor))
            else:
                raise SystemExit(
                    f"manager manifest has unexpected runnable platform {key[0]}/{key[1]}"
                )
            continue
        context = f"manager manifest {key[0]}/{key[1]}"
        variant = platform.get("variant")
        allowed_variants = {None, "v8"} if key == ("linux", "arm64") else {None}
        if variant not in allowed_variants:
            raise SystemExit(f"{context}: unsupported platform variant {variant!r}")
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

    attestation_digests: set[str] = set()
    for position, descriptor in attestations:
        context = f"manager attestation descriptor {position}"
        if descriptor.get("mediaType") not in IMAGE_MEDIA_TYPES:
            raise SystemExit(f"{context}: descriptor is not an image manifest")
        descriptor_digest(descriptor, context)
        if descriptor["digest"] in digests or descriptor["digest"] in attestation_digests:
            raise SystemExit(f"{context}: descriptor digest is not distinct")
        attestation_digests.add(descriptor["digest"])
        annotations = descriptor.get("annotations")
        if not isinstance(annotations, dict):
            raise SystemExit(f"{context}: missing attestation annotations")
        if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
            raise SystemExit(f"{context}: unknown descriptor identity")
        if annotations.get("vnd.docker.reference.digest") not in digests:
            raise SystemExit(f"{context}: does not reference a required platform image")
    return required


def validate_image_config(
    document: dict[str, Any],
    platform: tuple[str, str],
    revision: str,
    version: str,
    channel: str,
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
    canonical_version_label = version
    observed_version_label = labels.get("org.opencontainers.image.version")
    if observed_version_label != canonical_version_label:
        raise SystemExit(
            f"{context}: label org.opencontainers.image.version: "
            f"{observed_version_label!r} != {canonical_version_label!r}"
        )
    required = {
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.ref.name": channel,
        "io.leash.manager.contract.version": "1",
        "io.leash.manager.contract.min-compatible": "1",
    }
    for key, expected in required.items():
        if labels.get(key) != expected:
            raise SystemExit(
                f"{context}: label {key}: {labels.get(key)!r} != {expected!r}"
            )


def validate_registry(
    manifest_path: Path,
    image_paths: dict[tuple[str, str], Path],
    revision: str,
    digest: str,
    version: str,
    channel: str,
) -> None:
    if DIGEST_PATTERN.fullmatch(digest) is None:
        raise SystemExit(f"manager registry: invalid expected digest {digest!r}")
    observed_digest = f"sha256:{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}"
    if observed_digest != digest:
        raise SystemExit(
            f"manager registry digest {observed_digest!r} != expected {digest!r}"
        )
    index = load_json(manifest_path)
    required_descriptors(index)
    for platform, path in image_paths.items():
        document = load_json(path)
        validate_image_config(document, platform, revision, version, channel)


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


def validate_oci(
    archive_path: Path, revision: str, version: str, channel: str
) -> None:
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
            validate_image_config(config, platform, revision, version, channel)


def main() -> int:
    args = parse_args()
    if args.mode == "oci":
        validate_oci(args.archive, args.revision, args.version, args.channel)
    elif args.mode == "descriptor":
        descriptors = required_descriptors(load_json(args.manifest))
        platform = (args.os, args.arch)
        if platform not in descriptors:
            raise SystemExit(f"manager manifest missing {args.os}/{args.arch}")
        print(descriptors[platform]["digest"], end="")
    else:
        validate_registry(
            args.manifest,
            {
                ("linux", "amd64"): args.image_amd64,
                ("linux", "arm64"): args.image_arm64,
            },
            args.revision,
            args.digest,
            args.version,
            args.channel,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
