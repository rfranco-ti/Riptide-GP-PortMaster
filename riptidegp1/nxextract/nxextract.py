#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""NXExtract universal, transactional Android data extractor.

The external filename is deliberately never used to identify a game. Inputs are
classified by their contents and a small per-port JSON recipe selects and validates
the required payload.
"""

import argparse
import binascii
import contextlib
import errno
import fcntl
import fnmatch
import hashlib
import json
import os
import platform
import re
import select
import shutil
import signal
import stat
import string
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
import zipfile
from pathlib import Path, PurePosixPath


NXEXTRACT_VERSION = "1.3.0"
# Markers are runtime receipts, not engine executables. 1.2.21 can migrate the
# immediately preceding marker after authenticating the already installed
# payload; older layouts still fail closed and use the normal install path.
COMPATIBLE_MARKER_VERSIONS = (NXEXTRACT_VERSION, "1.2.21", "1.2.20")
FORMAT_VERSION = 1
TRANSACTION_FORMAT_VERSION = 2
TERMINAL_RESULT_SCHEMA = "org.nextos.nxextract.terminal-result"
TERMINAL_RESULT_SCHEMA_VERSION = 1
DEFAULT_TERMINAL_RESULT = "nxextract-result.json"
DEFAULT_DETAIL_LOG = "nxextract-detail.log"
# Declared log budgets.  These were a number in nx-budget-check and nothing
# else: NXExtract runs at install time on the same card the game lives on, so
# an unbounded log competes for space with the payloads it is extracting.  The
# compact log is the opening narrative (recipe identity, discovery, plan) and
# is capped, saying so on the last line it writes; the detail log is the
# lossless stream and rotates once, so the most recent window always survives.
COMPACT_LOG_CEILING = 2 * 1024 * 1024
DETAIL_LOG_CEILING = 8 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
DEFAULT_SAFETY_BYTES = 128 * 1024 * 1024
MAX_RECIPE_BYTES = 1024 * 1024
# V3-HARDENING-01: resource fences for recipe hooks (never applied to the
# game process). Recipes may LOWER them through hook.limits, never raise
# beyond these ceilings.
HOOK_LIMIT_CEILINGS = {
    "wall_seconds": 1800,
    "cpu_seconds": 1800,
    "memory_bytes": 4 * 1024 * 1024 * 1024,
    "fsize_bytes": 8 * 1024 * 1024 * 1024,
    "nproc": 256,
    "output_bytes": 64 * 1024 * 1024,
}
# nproc has PER-USER semantics (it counts every process of the uid, not the
# hook's own children); a low default breaks any shared-uid host or CFW where
# the frontend runs under the same user. It is therefore applied ONLY when a
# recipe declares it explicitly.
HOOK_LIMIT_DEFAULTS = {
    "wall_seconds": 300,
    "cpu_seconds": 300,
    "memory_bytes": 1024 * 1024 * 1024,
    "fsize_bytes": 2 * 1024 * 1024 * 1024,
    "nproc": None,
    "output_bytes": 4 * 1024 * 1024,
}
HOOK_LINE_LIMIT = 64 * 1024
DEFAULT_EXTENSIONS = (
    ".apk",
    ".apkm",
    ".apks",
    ".xapk",
    ".zip",
    ".obb",
)
APK_EXTENSIONS = (".apk",)
BUNDLE_EXTENSIONS = (".apkm", ".apks", ".xapk")
PHASES = (
    "PREPARING",
    "SCANNING FILES",
    "VALIDATING PACKAGES",
    "SELECTING DATA",
    "EXTRACTING DATA",
    "PROCESSING DATA",
    "VALIDATING DATA",
    "INSTALLING DATA",
    "READY",
)
PHASE_IDS = (
    "preparing",
    "scanning",
    "validating-packages",
    "selecting",
    "extracting",
    "processing",
    "validating-data",
    "installing",
    "ready",
)
ELF_MACHINES = {
    "arm": 40,
    "armeabi": 40,
    "armeabi-v7a": 40,
    "aarch64": 183,
    "arm64": 183,
    "arm64-v8a": 183,
    "x86": 3,
    "x86_64": 62,
}


# --- BEGIN APKCOMPAT CANONICAL (byte-identical to framework/contracts/apkcompat/apkcompat.py; sync-gated) ---
# SPDX-License-Identifier: GPL-3.0-only
# NXCOMPAT-APK -- canonical, dependency-free APK compatibility contract (V3).
#
# This module is the SINGLE source of truth for the rule that decides how a
# recipe may describe the owner-provided container (APK/APKM/APKS/XAPK).
# It is consumed by three layers:
#   - suportando_outros_devices/extrator-universal/nxextract.py (embedded copy,
#     byte-identity enforced by a sync gate in the tests of both sides),
#   - framework/nxgenerator/nxgenerator.py (imported by file path),
#   - framework/nxrelease/nxrelease.py (imported by file path).
#
# V3 permanent rule (APK-COMPAT-01):
#   Identity of the owner-provided container (sha256, crc32, exact size, file
#   name, signature, packaging tool, member order/timestamps, exact
#   versionCode, literal version text) must NEVER decide compatibility --
#   neither alone nor in a list of any length. Those values may appear only in
#   the documentation-only `reference_build` block. Compatibility is decided
#   by runtime contracts: package family, ABI, required structure/members,
#   engine/metadata format, ELF architecture and consumed symbols/interfaces.
#   Internal payload hashes may only SELECT a patch profile that really
#   depends on those bytes, and every profile must declare a generic/symbolic
#   fallback; a compatible-but-unknown build follows the fallback and is never
#   rejected for missing a whitelist.
#
# Error code family: NXA#### (APK compatibility).

APKCOMPAT_SCHEMA = "org.nextos.apk-compat"
APKCOMPAT_SCHEMA_VERSION = 3

import fnmatch as _fnmatch
import re as _re

# 64 hex digits used as an equality predicate.
_HEX64_RE = _re.compile(r"\b[0-9a-fA-F]{64}\b")
# Dotted literal version token with at least three numeric components
# (a five-component game build number, say). Two-component tokens are too common in honest
# text (schema versions, GLIBC) to flag by default.
_DOTTED_VERSION_RE = _re.compile(r"\b\d+(?:\.\d+){2,}\b")

CONTAINER_IDENTITY_KEYS = ("sha256", "crc32", "size")

PREDICATE_CLASSES = ("reference_identity", "compatibility", "patch_selection")

REFERENCE_BUILD_KEYS = (
    "game_version",
    "version_code",
    "container_size",
    "container_sha256",
    "note",
)

COMPATIBILITY_KEYS = (
    "package_families",
    "abis",
    "required_members",
    "payload_contracts",
    "required_symbols_or_interfaces",
)

PATCH_PROFILE_KEYS = ("id", "match_internal_payload", "fallback", "note")

MAX_REQUIRED_MEMBERS = 256
MAX_PATCH_PROFILES = 128
MAX_MEMBER_PATH = 1024

# Roles a declared required member may carry. A plain string defaults to
# core_required. core_required: present in EVERY compatible build. optional: may
# be absent (documented, never gates). variant_required: required only for a
# named variant. patch_selector: names bytes that pick a patch profile, it never
# gates acceptance on its own (a build missing it follows the fallback).
MEMBER_ROLES = (
    "core_required", "optional", "variant_required", "patch_selector",
)
# Container-identity keys that must NEVER gate acceptance (cosmetic identity of
# the owner-provided copy). A re-signed, renamed or versionCode-bumped build
# that is structurally identical stays compatible.
CONTAINER_COSMETIC_IDENTITY = (
    "signature", "signing_cert", "cert_sha1", "cert_sha256",
    "filename", "name", "version_code", "versionCode",
)
# A hex SHA-1 certificate fingerprint (40 hex) used as an equality predicate.
_HEX40_RE = _re.compile(r"\b[0-9a-fA-F]{40}\b")
_SIGNING_MEMBER_TEXT_RE = _re.compile(
    r"META-INF[/\\\\][^\s'\"]*(?:\.SF|\.RSA|\.DSA|\.EC|MANIFEST\.MF)",
    _re.IGNORECASE,
)

HOOK_CONTRACT_SCHEMA = "org.nextos.apk-compat.hook-contract"
HOOK_CONTRACT_SCHEMA_VERSION = 1
HOOK_CONTRACT_KEYS = (
    "schema",
    "schema_version",
    "hook_id",
    "inputs",
    "predicates",
    "patch_profiles",
    "fallback",
    "error_codes",
)


def _is_bool(value):
    return isinstance(value, bool)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value):
    return isinstance(value, str)


def _is_string_list(value):
    return isinstance(value, list) and all(
        _is_text(item) and item for item in value
    )


def _normalize_member_path(value, label, fail):
    """Return one canonical APK-member path, or ``None`` after reporting it.

    The canonical contract deliberately has no pathlib dependency.  These are
    the same portable path properties enforced by NXExtract when it opens a
    ZIP: relative POSIX spelling, no empty/dot traversal components, no
    control characters and no Windows-hostile trailing dot/space.
    """
    if not _is_text(value) or not value or len(value) > MAX_MEMBER_PATH:
        fail("NXA0026 %s must be a non-empty path of at most %d characters"
             % (label, MAX_MEMBER_PATH))
        return None
    if (value.startswith("/") or "\\" in value or "\x00" in value
            or any(ord(character) < 32 for character in value)):
        fail("NXA0026 %s is not a safe relative APK-member path: %r"
             % (label, value))
        return None
    parts = value.split("/")
    if any(part in ("", ".", "..") or ":" in part
           or part.endswith((" ", ".")) for part in parts):
        fail("NXA0026 %s is not a portable APK-member path: %r"
             % (label, value))
        return None
    return "/".join(parts)


def _is_signing_member(value):
    """Whether a member names Android/JAR signature or certificate material."""
    if not _is_text(value):
        return False
    upper = value.upper()
    if not upper.startswith("META-INF/"):
        return False
    name = upper.rsplit("/", 1)[-1]
    return (
        name == "MANIFEST.MF"
        or name == "STAMP-CERT-SHA256"
        or name.endswith((".SF", ".RSA", ".DSA", ".EC"))
    )


def _is_signing_member_pattern(value):
    """Conservative declarative check for a required signature-member rule."""
    if not _is_text(value):
        return False
    upper = value.replace("\\", "/").upper()
    name = upper.rsplit("/", 1)[-1]
    signing_name = (
        name == "MANIFEST.MF"
        or name == "STAMP-CERT-SHA256"
        or name.endswith((".SF", ".RSA", ".DSA", ".EC"))
    )
    if upper.startswith("META-INF/"):
        return signing_name or any(token in name for token in "*?[")
    if "/" not in upper or not signing_name:
        return False
    directory = upper.rsplit("/", 1)[0]
    return _fnmatch.fnmatchcase("META-INF", directory)


def validate_container_rule_identity(rule_id, validate_block, fail,
                                     field="validate"):
    """NXA0001..NXA0003: forbid container-identity predicates in ANY quantity.

    `validate_block` is one source-side validation object for a source of kind
    `container`. sha256/crc32 lists of ANY length and an exact `size` are
    identity of the owner-provided copy, never compatibility. Bounded size
    (min_size/max_size), magic and elf_machine remain allowed because they
    test structure, not identity.
    """
    if validate_block is None:
        return
    if not isinstance(validate_block, dict):
        fail("NXA0001 extract %s container %s must be an object"
             % (rule_id, field))
        return
    if "sha256" in validate_block:
        fail(
            "NXA0001 extract %s %s: sha256 of the owner-provided container is "
            "identity, not compatibility; it must not gate acceptance in any "
            "quantity (document only the tested container in reference_build)"
            % (rule_id, field)
        )
    if "crc32" in validate_block:
        fail(
            "NXA0002 extract %s %s: crc32 of the owner-provided container is "
            "identity, not compatibility; it must not gate acceptance in any "
            "quantity (document only the tested container in reference_build)"
            % (rule_id, field)
        )
    if "size" in validate_block:
        fail(
            "NXA0003 extract %s %s: exact container size is identity, not "
            "compatibility; use min_size/max_size bounds or omit it"
            % (rule_id, field)
        )
    if any(key in validate_block for key in (
            "signature", "signing_cert", "cert_sha1", "cert_sha256")):
        fail(
            "NXA0004 extract %s %s: the container signature/signing certificate is "
            "identity, not compatibility; it must not gate acceptance (a "
            "re-signed but structurally identical build stays compatible)"
            % (rule_id, field)
        )
    if "filename" in validate_block or "name" in validate_block:
        fail(
            "NXA0005 extract %s %s: the container file name is identity, not "
            "compatibility; a renamed but identical build stays compatible" %
            (rule_id, field)
        )
    if "version_code" in validate_block or "versionCode" in validate_block:
        fail(
            "NXA0006 extract %s %s: the exact versionCode is identity, not "
            "compatibility; decide by structure/members/ABI (a bumped build "
            "stays compatible) and document the code in reference_build" %
            (rule_id, field)
        )


def validate_container_source_identity(rule_id, source, fail):
    """NXA0005: an external container name may not narrow source selection."""
    if not isinstance(source, dict):
        return
    patterns = source.get("patterns")
    if patterns is None:
        return
    if not isinstance(patterns, list) or patterns != ["*"]:
        fail(
            "NXA0005 extract %s: container source.patterns must be exactly "
            "['*']; external file names and extensions never decide "
            "compatibility (select an APK split by its manifest split value)"
            % rule_id
        )


def validate_signing_member_rule(rule_id, source, fail):
    """NXA0004: extraction may not expose signing identity to later gates."""
    if not isinstance(source, dict):
        return
    if source.get("kind") not in ("entry", "entries", "entry_or_file"):
        return
    for pattern in source.get("patterns") or []:
        if _is_signing_member_pattern(pattern):
            fail(
                "NXA0004 extract %s: Android signature/certificate "
                "member pattern %r is container identity, not compatibility"
                % (rule_id, pattern)
            )


def validate_reference_build(block, fail):
    """NXA0010..NXA0012: documentation-only identity of the tested copy."""
    if block is None:
        return
    if not isinstance(block, dict):
        fail("NXA0010 reference_build must be an object")
        return
    for key in block:
        if key not in REFERENCE_BUILD_KEYS:
            fail(
                "NXA0011 reference_build.%s is not a documented field; only "
                "%s are allowed" % (key, ", ".join(REFERENCE_BUILD_KEYS))
            )
    for key, value in block.items():
        if key in ("container_size", "version_code"):
            if not (_is_int(value) or _is_text(value)):
                fail("NXA0012 reference_build.%s must be text or integer" % key)
        elif not _is_text(value):
            fail("NXA0012 reference_build.%s must be text" % key)


def validate_compatibility(block, fail, input_packages=None, abi_order=None):
    """NXA0020..NXA0026: the only block allowed to decide acceptance."""
    if block is None:
        return
    if not isinstance(block, dict):
        fail("NXA0020 compatibility must be an object")
        return
    for key in block:
        if key not in COMPATIBILITY_KEYS:
            fail(
                "NXA0021 compatibility.%s is unknown; allowed keys: %s"
                % (key, ", ".join(COMPATIBILITY_KEYS))
            )
    families = block.get("package_families")
    if families is not None:
        if not _is_string_list(families) or not families:
            fail("NXA0022 compatibility.package_families must be a non-empty string list")
        elif input_packages is not None:
            declared = {item.casefold() for item in families}
            engine = {item.casefold() for item in input_packages}
            if declared != engine:
                fail(
                    "NXA0023 compatibility.package_families must match "
                    "input.packages exactly (one source of decision)"
                )
    abis = block.get("abis")
    if abis is not None:
        if not _is_string_list(abis) or not abis:
            fail("NXA0024 compatibility.abis must be a non-empty string list")
        elif abi_order is not None:
            declared = {item.casefold() for item in abis}
            engine = {item.casefold() for item in abi_order}
            if declared != engine:
                fail(
                    "NXA0025 compatibility.abis must match abi_order exactly "
                    "(one source of decision)"
                )
    normalize_required_members(
        block.get("required_members"), fail, abi_order=abi_order
    )
    for key in ("payload_contracts", "required_symbols_or_interfaces"):
        value = block.get(key)
        if value is not None and not (
            isinstance(value, list)
            and all(_is_text(item) and item for item in value)
        ):
            fail("NXA0026 compatibility.%s must be a string list" % key)
    for item in block.get("payload_contracts") or []:
        if _is_text(item) and _HEX64_RE.search(item):
            fail(
                "NXA0027 compatibility.payload_contracts must describe "
                "structure, not carry a hash: %r" % item
            )


def normalize_required_members(members, fail, abi_order=None):
    """NXA0026..NXA0029: required_members may be plain member paths (each an
    implicit core_required) OR role-tagged objects {member, role[, variant]}.

    Roles (MEMBER_ROLES): core_required (in every compatible build), optional
    (may be absent, never gates), variant_required (required for a named
    variant), patch_selector (names bytes that pick a patch profile, never
    gates acceptance -- a build without it follows the fallback). A member path
    is structure, never a hash. Returns normalized dictionaries so the runtime
    consumes the exact same role interpretation that generator/release validate.
    """
    normalized = []
    if members is None:
        return normalized
    if not isinstance(members, list) or len(members) > MAX_REQUIRED_MEMBERS:
        fail("NXA0026 compatibility.required_members must be a list")
        return normalized
    variants = None
    if abi_order is not None:
        variants = {
            value.casefold(): value for value in abi_order
            if _is_text(value) and value
        }
    seen = set()
    for index, entry in enumerate(members):
        label = "compatibility.required_members[%d].member" % index
        role = "core_required"
        variant = None
        if _is_text(entry):
            member = entry
        elif isinstance(entry, dict):
            extra = set(entry) - {"member", "role", "variant"}
            if extra:
                fail(
                    "NXA0028 compatibility.required_members entry has unknown "
                    "key(s): %s" % ", ".join(sorted(extra))
                )
            member = entry.get("member")
            role = entry.get("role", "core_required")
            if role not in MEMBER_ROLES:
                fail(
                    "NXA0028 compatibility.required_members role must be one "
                    "of %s" % ", ".join(MEMBER_ROLES)
                )
            if role == "variant_required":
                variant = entry.get("variant")
                if not (_is_text(variant) and variant):
                    fail(
                        "NXA0029 compatibility.required_members variant_required "
                        "entry must name its variant"
                    )
                elif variants is None:
                    fail(
                        "NXA0029 compatibility.required_members "
                        "variant_required needs an explicit abi_order"
                    )
                elif variant.casefold() not in variants:
                    fail(
                        "NXA0029 compatibility.required_members variant %r "
                        "is not declared in abi_order" % variant
                    )
                else:
                    variant = variants[variant.casefold()]
            elif "variant" in entry:
                fail(
                    "NXA0029 compatibility.required_members variant is only "
                    "valid for role variant_required"
                )
        else:
            fail(
                "NXA0026 compatibility.required_members entry must be a member "
                "path or a {member, role} object"
            )
            continue
        member = _normalize_member_path(member, label, fail)
        if member is None:
            continue
        if _HEX64_RE.search(member):
            fail(
                "NXA0027 compatibility.required_members must describe "
                "structure, not carry a hash: %r" % member
            )
        if _is_signing_member(member):
            fail(
                "NXA0004 compatibility.required_members must not use Android "
                "signature/certificate member %r as a compatibility anchor"
                % member
            )
        key = member.casefold()
        if key in seen:
            fail(
                "NXA0028 compatibility.required_members contains duplicate or "
                "case-colliding member %r" % member
            )
            continue
        seen.add(key)
        record = {"member": member, "role": role}
        if role == "variant_required" and variant is not None:
            record["variant"] = variant
        normalized.append(record)
    return normalized


def validate_patch_profiles(block, fail):
    """NXA0030..NXA0035: authenticated internal-payload patch selection."""
    if block is None:
        return
    if not isinstance(block, list) or len(block) > MAX_PATCH_PROFILES:
        fail("NXA0030 patch_profiles must be a list")
        return
    seen = set()
    seen_matches = set()
    for index, profile in enumerate(block):
        label = "patch_profiles[%d]" % index
        if not isinstance(profile, dict):
            fail("NXA0030 %s must be an object" % label)
            continue
        for key in profile:
            if key not in PATCH_PROFILE_KEYS:
                fail("NXA0031 %s.%s is unknown" % (label, key))
        identifier = profile.get("id")
        if not _is_text(identifier) or not _re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", identifier or ""
        ):
            fail("NXA0032 %s.id must be 1-64 safe characters" % label)
        elif identifier.casefold() in seen:
            fail("NXA0032 duplicate patch profile id: %s" % identifier)
        else:
            seen.add(identifier.casefold())
        match = profile.get("match_internal_payload")
        if not isinstance(match, dict) or not match:
            fail(
                "NXA0033 %s.match_internal_payload must identify the internal "
                "payload bytes the patch depends on" % label
            )
        else:
            for key, value in match.items():
                if key not in ("path", "sha256", "magic_hex", "magic_ascii",
                               "magic_offset"):
                    fail("NXA0033 %s.match_internal_payload.%s is unknown" % (label, key))
            path = _normalize_member_path(
                match.get("path"), "%s.match_internal_payload.path" % label,
                fail,
            )
            if path is not None and _is_signing_member(path):
                fail(
                    "NXA0004 %s.match_internal_payload.path must not select "
                    "Android signature/certificate material" % label
                )
            sha = match.get("sha256")
            if not _is_text(sha) or not _re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
                fail(
                    "NXA0034 %s.match_internal_payload.sha256 is mandatory "
                    "and must be 64 hex; a patch profile is authenticated by "
                    "the internal payload bytes it depends on" % label
                )
            magic_hex = match.get("magic_hex")
            magic_ascii = match.get("magic_ascii")
            if magic_hex is not None and magic_ascii is not None:
                fail("NXA0034 %s may not combine magic_hex and magic_ascii" % label)
            if magic_hex is not None and (
                    not _is_text(magic_hex)
                    or not magic_hex
                    or len(magic_hex) % 2
                    or len(magic_hex) > 8192
                    or _re.fullmatch(r"[0-9a-fA-F]+", magic_hex) is None):
                fail("NXA0034 %s.match_internal_payload.magic_hex is invalid" % label)
            if magic_ascii is not None and (
                    not _is_text(magic_ascii)
                    or not magic_ascii
                    or len(magic_ascii) > 4096
                    or any(ord(character) > 127 for character in magic_ascii)):
                fail("NXA0034 %s.match_internal_payload.magic_ascii is invalid" % label)
            offset = match.get("magic_offset", 0)
            if (not _is_int(offset) or offset < 0 or offset > (1 << 40)):
                fail("NXA0034 %s.match_internal_payload.magic_offset is invalid" % label)
            if path is not None and _is_text(sha) and _re.fullmatch(
                    r"[0-9a-fA-F]{64}", sha):
                match_key = (
                    path.casefold(), sha.casefold(), magic_hex, magic_ascii,
                    offset,
                )
                if match_key in seen_matches:
                    fail("NXA0034 duplicate authenticated patch match in %s" % label)
                seen_matches.add(match_key)
        fallback = profile.get("fallback")
        if (not _is_text(fallback) or not fallback.strip()
                or len(fallback) > 256):
            fail(
                "NXA0035 %s.fallback is mandatory: a build that does not "
                "match the internal payload must follow the generic/symbolic "
                "path, never be rejected" % label
            )


def validate_patch_profile_links(compatibility, profiles, abi_order, fail):
    """NXA0036..NXA0038: selectors and profiles form one unambiguous graph."""
    if not isinstance(compatibility, dict):
        compatibility = {}
    members = normalize_required_members(
        compatibility.get("required_members"), fail, abi_order=abi_order
    )
    selectors = {
        item["member"].casefold(): item["member"]
        for item in members if item.get("role") == "patch_selector"
    }
    by_selector = {}
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            match = profile.get("match_internal_payload")
            if not isinstance(match, dict):
                continue
            path = match.get("path")
            if not _is_text(path):
                continue
            key = path.casefold()
            by_selector.setdefault(key, []).append(profile)
            if key not in selectors:
                fail(
                    "NXA0036 patch profile %r path %r has no matching "
                    "compatibility.required_members patch_selector"
                    % (profile.get("id"), path)
                )
    for key, member in selectors.items():
        linked = by_selector.get(key, [])
        if not linked:
            fail(
                "NXA0036 patch_selector %r must have at least one authenticated "
                "patch_profiles entry" % member
            )
            continue
        fallbacks = {
            profile.get("fallback") for profile in linked
            if _is_text(profile.get("fallback"))
        }
        if len(fallbacks) != 1:
            fail(
                "NXA0037 patch_selector %r profiles must declare one common "
                "generic/symbolic fallback" % member
            )


def validate_recipe_apk_compat(recipe, fail):
    """Entry point over a parsed recipe dict.

    Applies the container-identity ban to every extract rule of kind
    `container` and validates the optional V3 blocks. Purely additive:
    recipes without the V3 blocks stay valid as long as no container rule
    carries identity predicates.
    """
    if not isinstance(recipe, dict):
        fail("NXA0000 recipe must be an object")
        return
    rules = recipe.get("extract") or []
    container_destinations = {}
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            source = rule.get("source")
            if isinstance(source, dict) and source.get("kind") == "container":
                destination = rule.get("destination")
                if _is_text(destination):
                    if "{basename}" in destination:
                        fail(
                            "NXA0005 extract %s: a container destination may "
                            "not inherit the external basename; use one fixed "
                            "package-relative path" % rule.get("id", "?")
                        )
                    else:
                        container_destinations[destination.casefold()] = rule.get(
                            "id", "?"
                        )
                validate_container_source_identity(
                    rule.get("id", "?"), source, fail
                )
                validate_container_rule_identity(
                    rule.get("id", "?"), rule.get("validate"), fail,
                    "validate",
                )
                for phase_field in ("source_validate", "output_validate"):
                    if phase_field not in rule:
                        continue
                    validate_container_rule_identity(
                        rule.get("id", "?"), rule.get(phase_field), fail,
                        phase_field,
                    )
            validate_signing_member_rule(
                rule.get("id", "?"), source, fail,
            )

    def _validate_container_output_checks(checks, field):
        if not isinstance(checks, list):
            return
        for check in checks:
            if not isinstance(check, dict) or not _is_text(check.get("path")):
                continue
            rule_id = container_destinations.get(check["path"].casefold())
            if rule_id is not None:
                validate_container_rule_identity(rule_id, check, fail, field)

    _validate_container_output_checks(recipe.get("validate"), "validate output")
    hooks = recipe.get("hooks")
    if isinstance(hooks, list):
        for hook in hooks:
            if isinstance(hook, dict):
                _validate_container_output_checks(
                    hook.get("checkpoint"),
                    "hook %s checkpoint" % hook.get("id", "?"),
                )
    input_config = recipe.get("input")
    packages = None
    if isinstance(input_config, dict):
        value = input_config.get("packages")
        if _is_string_list(value):
            packages = value
    abi_order = recipe.get("abi_order")
    if not _is_string_list(abi_order):
        abi_order = None
    profiles = recipe.get("patch_profiles")
    validate_reference_build(recipe.get("reference_build"), fail)
    validate_compatibility(
        recipe.get("compatibility"), fail,
        input_packages=packages, abi_order=abi_order,
    )
    validate_patch_profiles(profiles, fail)
    validate_patch_profile_links(
        recipe.get("compatibility"), profiles, abi_order, fail
    )


def validate_hook_contract(document, hook_ids, fail):
    """NXA0040..NXA0047: hook-contract.json declared by custom hooks."""
    if not isinstance(document, dict):
        fail("NXA0040 hook contract must be a JSON object")
        return
    if document.get("schema") != HOOK_CONTRACT_SCHEMA:
        fail("NXA0041 hook contract schema must be %s" % HOOK_CONTRACT_SCHEMA)
    if document.get("schema_version") != HOOK_CONTRACT_SCHEMA_VERSION:
        fail(
            "NXA0041 hook contract schema_version must be %d"
            % HOOK_CONTRACT_SCHEMA_VERSION
        )
    for key in document:
        if key not in HOOK_CONTRACT_KEYS:
            fail("NXA0042 hook contract key %s is unknown" % key)
    hook_id = document.get("hook_id")
    if not _is_text(hook_id) or (hook_ids is not None and hook_id not in hook_ids):
        fail("NXA0043 hook contract hook_id must name a declared recipe hook")
    inputs = document.get("inputs")
    if not _is_string_list(inputs) or not inputs:
        fail("NXA0044 hook contract inputs must list the payload paths it reads")
    predicates = document.get("predicates")
    if not isinstance(predicates, list) or not predicates:
        fail("NXA0045 hook contract must declare at least one predicate")
        predicates = []
    for index, predicate in enumerate(predicates):
        label = "predicates[%d]" % index
        if not isinstance(predicate, dict):
            fail("NXA0045 %s must be an object" % label)
            continue
        klass = predicate.get("class")
        if klass not in PREDICATE_CLASSES:
            fail(
                "NXA0046 %s.class must be one of %s"
                % (label, ", ".join(PREDICATE_CLASSES))
            )
        if klass == "reference_identity":
            fail(
                "NXA0046 %s: reference_identity may be reported, never "
                "verified by a hook as an acceptance predicate" % label
            )
        description = predicate.get("checks")
        if not _is_text(description) or not description.strip():
            fail("NXA0046 %s.checks must describe the technical property" % label)
    validate_patch_profiles(document.get("patch_profiles"), fail)
    fallback = document.get("fallback")
    if not _is_text(fallback) or not fallback.strip():
        fail(
            "NXA0047 hook contract fallback is mandatory: unknown compatible "
            "builds follow the generic path"
        )
    codes = document.get("error_codes")
    if not _is_string_list(codes) or not codes:
        fail("NXA0047 hook contract error_codes must list stable codes")


def scan_static_suspects(text, label, allowed_hex64=(), allowed_versions=(),
                         allowed_sha1=()):
    """NXA0050..NXA0055: static defence over hook/validator source text.

    Returns a list of finding strings; the caller decides whether findings
    are fatal. Flags: equality against 64-hex literals, literal dotted
    version tokens, byte-size tables, absolute offsets without fallback, and
    40-hex SHA-1 certificate fingerprints. Exceptions must be explicit, narrow
    and justified by the caller through allowed_hex64/allowed_versions/
    allowed_sha1.
    """
    findings = []
    if not _is_text(text):
        return findings
    allowed_hex = {item.casefold() for item in allowed_hex64}
    for match in _HEX64_RE.finditer(text):
        if match.group(0).casefold() in allowed_hex:
            continue
        findings.append(
            "NXA0050 %s: 64-hex literal used by custom logic (%s...); "
            "container identity must not gate compatibility and internal "
            "hashes belong in patch_profiles with fallback"
            % (label, match.group(0)[:12])
        )
    allowed_sha1_hex = {item.casefold() for item in allowed_sha1}
    for match in _HEX40_RE.finditer(text):
        token = match.group(0)
        if token.casefold() in allowed_sha1_hex:
            continue
        # A 64-hex literal contains 40-hex substrings; do not double-flag one.
        if _HEX64_RE.search(text[max(0, match.start() - 24):match.end() + 24]):
            continue
        findings.append(
            "NXA0054 %s: 40-hex literal used by custom logic (%s...); a SHA-1 "
            "signing-certificate fingerprint is identity, not compatibility, "
            "and must never gate acceptance"
            % (label, token[:12])
        )
    signing_member = _SIGNING_MEMBER_TEXT_RE.search(text)
    if signing_member:
        findings.append(
            "NXA0055 %s: Android signature/certificate member referenced by "
            "custom logic (%s); signing identity may be documented but never "
            "gate compatibility" % (label, signing_member.group(0)[:80])
        )
    allowed_version_tokens = set(allowed_versions)
    for match in _DOTTED_VERSION_RE.finditer(text):
        token = match.group(0)
        if token in allowed_version_tokens:
            continue
        findings.append(
            "NXA0051 %s: literal dotted version token %r; version text "
            "inside assets is identity, not compatibility (the Terraria "
            "dot-4 vs dot-49 regression)" % (label, token)
        )
    for pattern, code, description in (
        (r"\bexpected_sizes?\s*[=:]\s*[\[{(]", "NXA0052",
         "table of exact sizes"),
        (r"\b(?:seek|offset)\s*[(=:]\s*0x[0-9a-fA-F]{4,}", "NXA0053",
         "absolute offset without a declared patch profile"),
    ):
        if _re.search(pattern, text):
            findings.append(
                "%s %s: %s used by custom logic; exact numbers of the "
                "reference copy require a patch profile with fallback"
                % (code, label, description)
            )
    return findings
# --- END APKCOMPAT CANONICAL ---


COMPATIBILITY_RESULT_SCHEMA = "org.nextos.nxextract.compatibility-result"
COMPATIBILITY_RESULT_SCHEMA_VERSION = 1
MAX_COMPATIBILITY_RESULT_BYTES = 64 * 1024


_OBS_SEQUENCE = [0]


def emit_obs_event(phase, status, reason_code, details=None):
    """Append one nx-event-v1 line to the launcher-provided events file.

    Best effort by contract: observability must never change the outcome of
    an extraction, so every failure here is swallowed. The sink and run_id
    come from the launcher (NXOBS_EVENTS_FILE / NXOBS_RUN_ID); without them
    this is a no-op. The file is opened append-only refusing symlinks and
    hardlinks, and each line is one self-contained JSON object.
    """
    sink = os.environ.get("NXOBS_EVENTS_FILE")
    run_id = os.environ.get("NXOBS_RUN_ID")
    if not sink or not run_id:
        return
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}", run_id):
        return
    try:
        _OBS_SEQUENCE[0] += 1
        record = {
            "schema": "nx-event-v1",
            "schema_version": 1,
            "run_id": run_id,
            "sequence": _OBS_SEQUENCE[0],
            "source": "extractor",
            "component": "nxextract",
            "component_version": NXEXTRACT_VERSION,
            "phase": str(phase)[:64],
            "status": str(status)[:16],
            "reason_code": str(reason_code)[:16],
            "monotonic_ns": time.monotonic_ns(),
        }
        if isinstance(details, dict) and details:
            record["details"] = {
                str(key)[:32]: str(value)[:96]
                for key, value in list(details.items())[:16]
            }
        with open_private_text_append(sink) as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
    except Exception:
        pass


class NXError(Exception):
    """Expected, user-facing setup failure."""


class RecipeError(NXError):
    pass


class SourceError(NXError):
    pass


class PlanError(NXError):
    pass


class ValidationError(NXError):
    pass


# P13: causas de I/O que o campo realmente produz, separadas por errno.
# A TELA nao muda -- o codigo ocupa o mesmo lugar de sempre, e o launcher ja
# valida qualquer NXE#### pelo formato. O que muda e o suporte conseguir
# distinguir "cartao cheio" de "somente leitura" sem pedir log.
OS_ERROR_CODES = (
    ("NXE6002", (errno.ENOSPC, getattr(errno, "EDQUOT", None), errno.EFBIG)),
    ("NXE6003", (errno.EACCES, errno.EPERM, errno.EROFS)),
    ("NXE6004", (errno.ENOENT, errno.ENOTDIR, errno.ENAMETOOLONG)),
    ("NXE6005", (errno.EIO, errno.ENODEV, errno.ENXIO,
                 getattr(errno, "EREMOTEIO", None), errno.ESTALE)),
)


def os_error_code(error):
    """Separa o NXE6001 historico por causa, sem inventar categoria nova."""
    number = getattr(error, "errno", None)
    if number is None:
        return "NXE6001"
    for code, numbers in OS_ERROR_CODES:
        if number in [item for item in numbers if item is not None]:
            return code
    return "NXE6001"


def stable_error_code(error):
    """Map failures to a finite support code without parsing prose."""
    if isinstance(error, RecipeError):
        return "NXE1001"
    if isinstance(error, zipfile.BadZipFile):
        return "NXE2002"
    if isinstance(error, SourceError):
        return "NXE2001"
    if isinstance(error, PlanError):
        return "NXE3001"
    if isinstance(error, ValidationError):
        return "NXE4001"
    if isinstance(error, NotImplementedError):
        return "NXE5002"
    if isinstance(error, RuntimeError):
        return "NXE5001"
    if isinstance(error, OSError):
        return os_error_code(error)
    if isinstance(error, NXError):
        return "NXE7001"
    return "NXE9001"


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecipeError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=_json_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecipeError("cannot read JSON %s: %s" % (path, error))


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def is_regular_file(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def is_private_regular_file(path):
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def _verified_regular_descriptor(path, flags, mode=0o600, single_link=True):
    descriptor = os.open(
        path,
        flags
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        descriptor_info = os.fstat(descriptor)
        path_info = os.lstat(path)
        if (
            not stat.S_ISREG(descriptor_info.st_mode)
            or (single_link and descriptor_info.st_nlink != 1)
            or descriptor_info.st_dev != path_info.st_dev
            or descriptor_info.st_ino != path_info.st_ino
        ):
            raise NXError("unsafe linked or replaced regular file: %s" % path)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_private_text_append(path):
    descriptor = _verified_regular_descriptor(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
    )
    return os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)


def _assert_private_session_descriptor(descriptor, identity=None):
    """P1 item 3: valida um descritor do canal privado da sessao da UI.

    O contrato exige, antes do spawn e a cada uso, dono do processo, tipo
    FIFO, modo privado e identidade dev/ino exata; qualquer divergencia e'
    falha fechada. Um descritor substituido (dup2 de outro objeto sobre o
    mesmo numero) muda a identidade e e' recusado."""
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise NXError("UI session channel descriptor is unusable: %s" % error)
    if not stat.S_ISFIFO(info.st_mode):
        raise NXError("UI session channel is not a private pipe")
    if info.st_uid != os.geteuid():
        raise NXError("UI session channel is not owned by this user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise NXError("UI session channel mode is not private")
    if identity is not None and (info.st_dev, info.st_ino) != identity:
        raise NXError("UI session channel descriptor was replaced")
    return (info.st_dev, info.st_ino)


def create_private_ui_session_channels():
    """P1 item 2: o plano de controle da UI vive em descritores herdados.

    Dois pipes criados no processo pai, antes da UI: um para a prova de
    renderer visivel (UI escreve, motor le) e um para o pedido de parada
    (motor escreve, UI le). Nenhum pathname de sessao existe, entao a
    reciclagem do XDG_RUNTIME_DIR (Linger=no), um /tmp sem sticky bit ou um
    filesystem FAT/exFAT sem semantica de chmod nao alcancam o handshake.
    O XDG_RUNTIME_DIR exportado ao Wayland nao e' tocado. Se o motor morrer,
    o fechamento do pipe de parada encerra a UI sem processo orfao."""
    descriptors = {}
    try:
        (
            descriptors["ready_read"],
            descriptors["ready_write"],
        ) = os.pipe()
        (
            descriptors["stop_read"],
            descriptors["stop_write"],
        ) = os.pipe()
        identities = {
            name: _assert_private_session_descriptor(descriptor)
            for name, descriptor in descriptors.items()
        }
        return descriptors, identities
    except BaseException:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def validate_relative_path(value, label="path", allow_dot=False):
    if not isinstance(value, str):
        raise RecipeError("%s must be a string" % label)
    if "\x00" in value or "\\" in value or any(ord(char) < 32 for char in value):
        raise RecipeError("unsafe %s: %r" % (label, value))
    if value == "." and allow_dot:
        return value
    if not value or value.startswith("/"):
        raise RecipeError("unsafe %s: %r" % (label, value))
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RecipeError("unsafe %s: %r" % (label, value))
    if any(part.endswith((" ", ".")) for part in parts):
        raise RecipeError("non-portable %s component: %r" % (label, value))
    return "/".join(parts)


def portable_path_key(value):
    return unicodedata.normalize("NFC", value).casefold()


def safe_zip_name(name, directory=False):
    if not isinstance(name, str):
        raise SourceError("ZIP entry name is not text")
    if "\x00" in name or "\\" in name or any(ord(char) < 32 for char in name):
        raise SourceError("unsafe ZIP entry name: %r" % name)
    if name.startswith("/"):
        raise SourceError("unsafe absolute ZIP entry: %r" % name)
    clean = name[:-1] if directory and name.endswith("/") else name
    if not clean:
        return ""
    parts = clean.split("/")
    if any(
        part in ("", ".", "..")
        or ":" in part
        or part.endswith((" ", "."))
        for part in parts
    ):
        raise SourceError("unsafe ZIP entry path: %r" % name)
    return "/".join(parts)


def safe_join(root, relative, label="destination"):
    relative = validate_relative_path(relative, label)
    root = os.path.realpath(root)
    destination = os.path.abspath(os.path.join(root, *relative.split("/")))
    try:
        inside = os.path.commonpath((root, destination)) == root
    except ValueError:
        inside = False
    if not inside:
        raise NXError("%s escapes its root: %s" % (label, relative))
    return destination


def resolve_real_directory(path, label):
    original = os.path.abspath(os.fspath(path))
    try:
        mode = os.lstat(original).st_mode
    except OSError as error:
        raise NXError("%s is unavailable: %s" % (label, error))
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise NXError("%s is linked or not a directory" % label)
    return os.path.realpath(original)


def recipe_for_game(path, game_dir):
    original = os.path.abspath(os.fspath(path))
    try:
        contained = os.path.commonpath((game_dir, original)) == game_dir
    except ValueError:
        contained = False
    if not contained:
        raise RecipeError("recipe must be a regular file inside the game directory")
    relative = os.path.relpath(original, game_dir).replace(os.sep, "/")
    validate_relative_path(relative, "recipe path")
    ensure_no_symlink_parents(game_dir, relative)
    if not is_private_regular_file(original):
        raise RecipeError(
            "recipe must be a private regular file inside the game directory"
        )
    recipe = Recipe(original)
    protected = {
        portable_path_key(recipe.marker): "installation marker",
        portable_path_key(recipe.data.get("log", "nxextract.log")): "log",
        portable_path_key(recipe.detail_log): "detail log",
        portable_path_key(recipe.terminal_result): "terminal result",
    }
    if portable_path_key(relative) in protected:
        raise RecipeError(
            "recipe path collides with its %s" % protected[portable_path_key(relative)]
        )
    return recipe


def private_workspace_file(workspace, value, label):
    candidate = os.path.abspath(os.fspath(value))
    relative = os.path.relpath(candidate, workspace).replace(os.sep, "/")
    validate_relative_path(relative, label)
    path = safe_join(workspace, relative, label)
    ensure_no_symlink_parents(workspace, relative)
    ensure_real_parent_directories(workspace, relative)
    if os.path.lexists(path) and not is_private_regular_file(path):
        raise NXError("%s must be a private regular file" % label)
    return path


def private_game_file(game_dir, value, label):
    """Resolve one persistent extractor output without leaving the port tree."""
    candidate = os.path.abspath(os.fspath(value))
    relative = os.path.relpath(candidate, game_dir).replace(os.sep, "/")
    validate_relative_path(relative, label)
    path = safe_join(game_dir, relative, label)
    ensure_no_symlink_parents(game_dir, relative)
    ensure_real_parent_directories(game_dir, relative)
    if os.path.lexists(path) and not is_private_regular_file(path):
        raise NXError("%s must be a private regular file" % label)
    return path, relative


def ensure_no_symlink_parents(root, relative):
    root = os.path.realpath(root)
    current = root
    parts = validate_relative_path(relative).split("/")[:-1]
    for part in parts:
        current = os.path.join(current, part)
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise NXError("unsafe non-directory parent: %s" % current)


def ensure_real_parent_directories(root, relative):
    """Create relative parents one component at a time without following links."""
    root = os.path.realpath(root)
    current = root
    for part in validate_relative_path(relative).split("/")[:-1]:
        current = os.path.join(current, part)
        try:
            os.mkdir(current)
        except FileExistsError:
            pass
        try:
            mode = os.lstat(current).st_mode
        except OSError as error:
            raise NXError("parent directory is unavailable: %s (%s)" % (current, error))
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise NXError("unsafe non-directory parent: %s" % current)


def remove_path(path):
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def discard_path(path, logger=None, label=None):
    """Drop a scratch path without ever failing the run.

    FUSE-backed shares (exFAT on Knulli/Batocera, NFS, SMB) replace a file that
    is unlinked while still open with a hidden placeholder, so the parent
    directory can answer ENOTEMPTY even after every real entry is gone. Scratch
    space that survives one extra run is harmless; a committed payload reported
    as a failure is not.
    """
    try:
        remove_path(path)
        return True
    except OSError as error:
        failure = error
    shutil.rmtree(path, ignore_errors=True)
    if not os.path.lexists(path):
        return True
    if logger is not None:
        _best_effort_log(
            logger,
            "warning: kept %s for the next run (%s)" % (label or path, failure),
        )
    return False


def _best_effort_log(logger, message):
    """Report post-publication cleanup without making it a new failure."""
    if logger is None:
        return
    try:
        logger.log(message)
    except OSError:
        pass


def fsync_directory(path, required=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        if required:
            raise
        return False
    try:
        os.fsync(descriptor)
    except OSError:
        if required:
            raise
        return False
    finally:
        os.close(descriptor)
    return True


def durable_rename(source, destination):
    """Rename one transaction path and persist both directory entries."""
    source_parent = os.path.dirname(source) or "."
    destination_parent = os.path.dirname(destination) or "."
    os.rename(source, destination)
    fsync_directory(source_parent, required=True)
    if os.path.realpath(destination_parent) != os.path.realpath(source_parent):
        fsync_directory(destination_parent, required=True)


def _transaction_transition(_name, _journal):
    """Test seam used to audit every durable transaction boundary."""
    return None


def atomic_write(path, data, mode="w", required_directory_sync=False):
    path = os.fspath(path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    basename = os.path.basename(path)
    if basename in ("", ".", ".."):
        raise NXError("atomic write has an unsafe target name: %s" % path)
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary = ".%s.tmp.%d.%s" % (
        basename,
        os.getpid(),
        uuid.uuid4().hex,
    )
    binary = "b" in mode
    descriptor = None
    try:
        kwargs = {} if binary else {"encoding": "utf-8", "newline": "\n"}
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        with os.fdopen(descriptor, mode, **kwargs) as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(
            temporary,
            basename,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        try:
            os.fsync(parent_descriptor)
        except OSError:
            if required_directory_sync:
                raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)


def atomic_write_json(path, value, required_directory_sync=False):
    atomic_write(
        path,
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        required_directory_sync=required_directory_sync,
    )


def file_size(path):
    return os.stat(path, follow_symlinks=False).st_size


def file_crc32(path):
    value = 0
    with open(path, "rb") as stream:
        while True:
            block = stream.read(CHUNK_SIZE)
            if not block:
                return value & 0xFFFFFFFF
            value = binascii.crc32(block, value)


def file_sha256(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            block = stream.read(CHUNK_SIZE)
            if not block:
                return value.hexdigest()
            value.update(block)


def human_bytes(value):
    value = int(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            if unit == "B":
                return "%d %s" % (int(amount), unit)
            return "%.1f %s" % (amount, unit)
        amount /= 1024.0
    return "%d B" % value


def normalize_hash_list(value, name):
    if value is None:
        return ()
    values = value if isinstance(value, list) else [value]
    result = []
    for item in values:
        if not isinstance(item, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", item):
            raise RecipeError("%s must contain SHA-256 hex strings" % name)
        result.append(item.lower())
    return tuple(result)


def normalize_crc_list(value, name):
    if value is None:
        return ()
    values = value if isinstance(value, list) else [value]
    result = []
    for item in values:
        if isinstance(item, int):
            number = item
        elif isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{1,8}", item):
            number = int(item, 16)
        else:
            raise RecipeError("%s must contain CRC32 values" % name)
        if number < 0 or number > 0xFFFFFFFF:
            raise RecipeError("%s CRC32 is out of range" % name)
        result.append(number)
    return tuple(result)


def parse_magic(spec):
    if "magic_hex" in spec and "magic_ascii" in spec:
        raise RecipeError("validation cannot contain both magic_hex and magic_ascii")
    if "magic_hex" in spec:
        value = spec["magic_hex"]
        if not isinstance(value, str) or len(value) % 2 or not re.fullmatch(
            r"[0-9a-fA-F]*", value
        ):
            raise RecipeError("magic_hex must be an even-length hexadecimal string")
        return bytes.fromhex(value)
    if "magic_ascii" in spec:
        value = spec["magic_ascii"]
        if not isinstance(value, str):
            raise RecipeError("magic_ascii must be a string")
        try:
            return value.encode("ascii")
        except UnicodeEncodeError:
            raise RecipeError("magic_ascii must contain only ASCII")
    return None


def validate_template_fields(value, allowed, label):
    if not isinstance(value, str):
        raise RecipeError("%s must be text" % label)
    try:
        fields = string.Formatter().parse(value)
        for _literal, field_name, format_spec, conversion in fields:
            if field_name is None:
                continue
            if (
                field_name not in allowed
                or format_spec
                or conversion is not None
            ):
                raise RecipeError(
                    "%s contains unsupported template field: %r"
                    % (label, field_name)
                )
    except ValueError as error:
        raise RecipeError("%s contains an invalid template: %s" % (label, error))


def paths_overlap(left, right):
    left_key = portable_path_key(left.rstrip("/"))
    right_key = portable_path_key(right.rstrip("/"))
    return (
        left_key == right_key
        or left_key.startswith(right_key + "/")
        or right_key.startswith(left_key + "/")
    )


class Recipe:
    def __init__(self, path):
        original = os.path.abspath(os.fspath(path))
        if not is_regular_file(original):
            raise RecipeError("recipe is missing, linked or not a regular file: %s" % path)
        self.path = os.path.realpath(original)
        self.root = os.path.dirname(self.path)
        try:
            if os.path.getsize(self.path) > MAX_RECIPE_BYTES:
                raise RecipeError(
                    "recipe exceeds the %d-byte hardening ceiling"
                    % MAX_RECIPE_BYTES
                )
        except OSError as error:
            raise RecipeError("cannot inspect recipe: %s" % error)
        self.data = load_json(self.path)
        self._validate()
        self.digest = sha256_bytes(canonical_json(self.data))

    def _validate(self):
        data = self.data
        if not isinstance(data, dict):
            raise RecipeError("recipe root must be a JSON object")
        if data.get("schema") != FORMAT_VERSION:
            raise RecipeError(
                "unsupported recipe schema %r (expected %d)"
                % (data.get("schema"), FORMAT_VERSION)
            )
        identifier = data.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", identifier
        ):
            raise RecipeError("recipe id must be 1-64 safe characters")
        version = data.get("version")
        if (
            not isinstance(version, (str, int))
            or isinstance(version, bool)
            or not str(version)
            or len(str(version)) > 128
            or any(ord(character) < 32 for character in str(version))
        ):
            raise RecipeError("recipe version is required")
        title = data.get("title", identifier)
        if not isinstance(title, str) or not title.strip():
            raise RecipeError("recipe title must be text")
        input_config = data.get("input", {})
        if not isinstance(input_config, dict):
            raise RecipeError("input must be an object")
        self._validate_input_config(input_config)
        space = data.get("space", {})
        if not isinstance(space, dict):
            raise RecipeError("space must be an object")
        safety = space.get("safety_bytes", DEFAULT_SAFETY_BYTES)
        if (
            not isinstance(safety, int)
            or isinstance(safety, bool)
            or safety < 0
        ):
            raise RecipeError("space.safety_bytes must be a non-negative integer")
        log = data.get("log", "nxextract.log")
        detail_log = data.get("detail_log", DEFAULT_DETAIL_LOG)
        terminal_result = data.get("result", DEFAULT_TERMINAL_RESULT)
        if terminal_result != DEFAULT_TERMINAL_RESULT:
            raise RecipeError(
                "result path is fixed at %s for launcher interoperability"
                % DEFAULT_TERMINAL_RESULT
            )
        validate_relative_path(log, "log path")
        validate_relative_path(detail_log, "detail log path")
        validate_relative_path(terminal_result, "terminal result path")
        if len(log) > 512 or len(detail_log) > 512:
            raise RecipeError("log paths must not exceed 512 characters")
        protected_outputs = (
            (log, "log"),
            (detail_log, "detail log"),
            (terminal_result, "terminal result"),
        )
        for index, (left, left_label) in enumerate(protected_outputs):
            for right, right_label in protected_outputs[index + 1 :]:
                if paths_overlap(left, right):
                    raise RecipeError(
                        "%s and %s paths must not overlap"
                        % (left_label, right_label)
                    )
        for delay_name in ("ui_success_seconds", "ui_error_seconds"):
            delay = data.get(delay_name, 1 if delay_name == "ui_success_seconds" else 5)
            if (
                not isinstance(delay, (int, float))
                or isinstance(delay, bool)
                or delay < 0
                or delay > 300
            ):
                raise RecipeError("%s must be between 0 and 300" % delay_name)
        rules = data.get("extract")
        if not isinstance(rules, list) or not rules or len(rules) > 256:
            raise RecipeError("recipe extract must contain 1-256 rules")
        seen = set()
        for index, rule in enumerate(rules):
            self._validate_rule(rule, index, seen)
        self._validate_container_contract(input_config, rules)
        commit = data.get("commit")
        if not isinstance(commit, list) or not commit:
            raise RecipeError("recipe commit must be a non-empty list")
        normalized = []
        for index, item in enumerate(commit):
            if not isinstance(item, str):
                raise RecipeError("commit[%d] must be a string" % index)
            validate_template_fields(item, {"abi"}, "commit[%d]" % index)
            validate_relative_path(
                item.replace("{abi}", "ABI"), "commit[%d]" % index
            )
            normalized.append(item)
        for left_index, left in enumerate(normalized):
            for right in normalized[left_index + 1 :]:
                left_plain = left.replace("{abi}", "ABI")
                right_plain = right.replace("{abi}", "ABI")
                left_key = portable_path_key(left_plain)
                right_key = portable_path_key(right_plain)
                if left_key == right_key:
                    raise RecipeError("duplicate commit path: %s" % left)
                if left_key.startswith(right_key + "/") or right_key.startswith(
                    left_key + "/"
                ):
                    raise RecipeError(
                        "overlapping commit paths are not allowed: %s / %s"
                        % (left, right)
                    )
        mutable = data.get("mutable", [])
        if (not isinstance(mutable, list) or len(mutable) > 32 or
                any(not isinstance(item, str) for item in mutable)):
            raise RecipeError("mutable must be a list of at most 32 paths")
        for item in mutable:
            validate_relative_path(item, "mutable path")
            if "{abi}" in item:
                raise RecipeError("mutable path must not use {abi}: %s" % item)
            if not any(
                portable_path_key(item) == portable_path_key(plain)
                or portable_path_key(item).startswith(
                    portable_path_key(plain) + "/")
                for plain in (
                    entry.replace("{abi}", "ABI") for entry in normalized)):
                raise RecipeError(
                    "mutable path must live under a commit path: %s" % item)
        if len({portable_path_key(item) for item in mutable}) != len(mutable):
            raise RecipeError("duplicate mutable path")
        marker = data.get("marker", ".nxextract-%s.json" % identifier)
        validate_relative_path(marker, "marker")
        if paths_overlap(marker, log):
            raise RecipeError("marker and log paths must not overlap")
        for item in normalized:
            plain = item.replace("{abi}", "ABI")
            for protected, label in (
                (".nxextract", "private workspace"),
                (marker, "installation marker"),
                (log, "log"),
                (detail_log, "detail log"),
                (terminal_result, "terminal result"),
            ):
                if paths_overlap(plain, protected):
                    raise RecipeError(
                        "commit path %s overlaps the %s" % (item, label)
                    )
        for protected, label in (
            (marker, "marker"),
            (log, "log"),
            (detail_log, "detail log"),
            (terminal_result, "terminal result"),
        ):
            if paths_overlap(protected, ".nxextract"):
                raise RecipeError("%s path overlaps the private workspace" % label)
        for protected, label in (
            (log, "log"),
            (detail_log, "detail log"),
            (terminal_result, "terminal result"),
        ):
            if paths_overlap(marker, protected):
                raise RecipeError("marker and %s paths must not overlap" % label)
        hooks = data.get("hooks", [])
        if not isinstance(hooks, list):
            raise RecipeError("hooks must be a list")
        hook_ids = set()
        for index, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                raise RecipeError("hooks[%d] must be an object" % index)
            hook_id = hook.get("id")
            if not isinstance(hook_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", hook_id
            ):
                raise RecipeError("hooks[%d].id is invalid" % index)
            if hook_id in hook_ids:
                raise RecipeError("duplicate hook id: %s" % hook_id)
            hook_ids.add(hook_id)
            argv = hook.get("argv")
            if not isinstance(argv, list) or not argv or not all(
                isinstance(item, str) and item for item in argv
            ):
                raise RecipeError("hook %s argv must be a non-empty string list" % hook_id)
            for value in argv:
                validate_template_fields(
                    value,
                    {"game_dir", "stage", "workspace", "recipe_dir", "abi"},
                    "hook %s argv" % hook_id,
                )
            cwd = hook.get("cwd", "{game_dir}")
            if not isinstance(cwd, str) or not cwd:
                raise RecipeError("hook %s cwd must be text" % hook_id)
            validate_template_fields(
                cwd,
                {"game_dir", "stage", "workspace", "recipe_dir", "abi"},
                "hook %s cwd" % hook_id,
            )
            environment = hook.get("env", {})
            if not isinstance(environment, dict) or not all(
                isinstance(key, str)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                and isinstance(value, str)
                for key, value in environment.items()
            ):
                raise RecipeError("hook %s env must contain safe string assignments" % hook_id)
            reserved_environment = sorted(
                key for key in environment if key.startswith("NXEXTRACT_")
            )
            if reserved_environment:
                raise RecipeError(
                    "hook %s env may not override reserved engine variable(s): %s"
                    % (hook_id, ", ".join(reserved_environment))
                )
            for value in environment.values():
                validate_template_fields(
                    value,
                    {"game_dir", "stage", "workspace", "recipe_dir", "abi"},
                    "hook %s environment" % hook_id,
                )
            checks = hook.get("checkpoint", [])
            if not isinstance(checks, list):
                raise RecipeError("hook %s checkpoint must be a list" % hook_id)
            for check in checks:
                self._validate_output_check(check, "hook %s checkpoint" % hook_id)
            transactional = hook.get("transactional", False)
            if not isinstance(transactional, bool):
                raise RecipeError(
                    "hook %s transactional must be a boolean" % hook_id
                )
            limits = hook.get("limits", {})
            if not isinstance(limits, dict):
                raise RecipeError("hook %s limits must be an object" % hook_id)
            for name, ceiling in HOOK_LIMIT_CEILINGS.items():
                if name not in limits:
                    continue
                value = limits[name]
                if (not isinstance(value, int) or isinstance(value, bool)
                        or value < 1 or value > ceiling):
                    raise RecipeError(
                        "hook %s limits.%s must be an integer within 1..%d"
                        % (hook_id, name, ceiling)
                    )
            for name in limits:
                if name not in HOOK_LIMIT_CEILINGS:
                    raise RecipeError(
                        "hook %s limits.%s is unknown" % (hook_id, name)
                    )
            contract = hook.get("contract")
            if contract is not None:
                def _fail_contract(message, _hook=hook_id):
                    raise RecipeError("hook %s contract: %s" % (_hook, message))

                validate_hook_contract(contract, {hook_id}, _fail_contract)
        checks = data.get("validate", [])
        if not isinstance(checks, list):
            raise RecipeError("validate must be a list")
        for check in checks:
            self._validate_output_check(check, "validate")

        abi_order = data.get("abi_order")
        if abi_order is not None:
            if not isinstance(abi_order, list) or not abi_order:
                raise RecipeError("abi_order must be a non-empty string list")
            seen_abis = set()
            for abi in abi_order:
                if not isinstance(abi, str) or not re.fullmatch(
                    r"[A-Za-z0-9._-]{1,64}", abi
                ):
                    raise RecipeError("abi_order contains an invalid ABI")
                key = abi.casefold()
                if key in seen_abis:
                    raise RecipeError("abi_order contains a duplicate ABI")
                seen_abis.add(key)

    def _validate_container_contract(self, input_config, rules):
        containers = [
            rule for rule in rules if rule["source"]["kind"] == "container"
        ]
        if containers and not input_config.get("packages"):
            raise RecipeError(
                "container extraction requires input.packages; the external APK "
                "identity alone must not identify the game"
            )
        # V3 (APK-COMPAT-01): container identity (sha256/crc32/exact size)
        # never decides compatibility, in ANY quantity. The canonical rule
        # lives in the embedded APKCOMPAT module; identity of the tested copy
        # belongs in the documentation-only reference_build block.
        def _fail(message):
            raise RecipeError(message)

        validate_recipe_apk_compat(self.data, _fail)

    def _validate_input_config(self, config):
        extensions = config.get("extensions", list(DEFAULT_EXTENSIONS))
        if not isinstance(extensions, list) or not extensions:
            raise RecipeError("input.extensions must be a non-empty list")
        seen_extensions = set()
        for extension in extensions:
            if (
                not isinstance(extension, str)
                or re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9._+-]{0,31}", extension)
                is None
            ):
                raise RecipeError("input.extensions contains an invalid extension")
            key = extension.casefold()
            if key in seen_extensions:
                raise RecipeError("input.extensions contains a duplicate")
            seen_extensions.add(key)

        search_dirs = config.get("search_dirs", ["gamedata", "."])
        if not isinstance(search_dirs, list) or not search_dirs:
            raise RecipeError("input.search_dirs must be a non-empty list")
        seen_directories = set()
        for directory in search_dirs:
            if directory != ".":
                validate_relative_path(directory, "input search directory")
            if not isinstance(directory, str):
                raise RecipeError("input search directory must be text")
            key = portable_path_key(directory)
            if key in seen_directories:
                raise RecipeError("input.search_dirs contains a duplicate")
            seen_directories.add(key)

        for name in ("prefer_first_nonempty", "sniff_all_in_primary"):
            if name in config and not isinstance(config[name], bool):
                raise RecipeError("input.%s must be boolean" % name)

        limits = {
            "max_files": (1, 4096),
            "max_bundle_apks": (1, 4096),
            "max_member_bytes": (1, 1 << 50),
            "max_bundle_bytes": (1, 1 << 50),
        }
        for name, bounds in limits.items():
            if name not in config:
                continue
            value = config[name]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < bounds[0]
                or value > bounds[1]
            ):
                raise RecipeError("input.%s is out of range" % name)

        if "packages" in config:
            packages = config["packages"]
            if not isinstance(packages, list) or not packages:
                raise RecipeError("input.packages must be a non-empty list")
            seen_packages = set()
            for package in packages:
                if (
                    not isinstance(package, str)
                    or len(package) > 255
                    or re.fullmatch(
                        r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+",
                        package,
                    )
                    is None
                ):
                    raise RecipeError("input.packages contains an invalid package")
                key = package.casefold()
                if key in seen_packages:
                    raise RecipeError("input.packages contains a duplicate")
                seen_packages.add(key)

    def _validate_rule(self, rule, index, seen):
        if not isinstance(rule, dict):
            raise RecipeError("extract[%d] must be an object" % index)
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", rule_id
        ):
            raise RecipeError("extract[%d].id is invalid" % index)
        if rule_id in seen:
            raise RecipeError("duplicate extract id: %s" % rule_id)
        seen.add(rule_id)
        source = rule.get("source")
        if not isinstance(source, dict):
            raise RecipeError("extract %s source must be an object" % rule_id)
        kind = source.get("kind")
        if kind not in ("entry", "entries", "file", "entry_or_file", "container"):
            raise RecipeError("extract %s has unsupported source kind" % rule_id)
        patterns = source.get("patterns", ["*"])
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(item, str) and item for item in patterns
        ):
            raise RecipeError("extract %s patterns must be a non-empty string list" % rule_id)
        for pattern in patterns:
            validate_template_fields(
                pattern, {"abi"}, "extract %s pattern" % rule_id
            )
        scopes = source.get("scopes", ["apk", "bundle"])
        if not isinstance(scopes, list) or not scopes or not all(
            item in ("apk", "bundle") for item in scopes
        ):
            raise RecipeError("extract %s scopes must contain apk and/or bundle" % rule_id)
        if len(set(scopes)) != len(scopes):
            raise RecipeError("extract %s scopes contains a duplicate" % rule_id)
        file_extensions = source.get("file_extensions", [])
        if not isinstance(file_extensions, list):
            raise RecipeError("extract %s file_extensions must be a list" % rule_id)
        for extension in file_extensions:
            if (
                not isinstance(extension, str)
                or re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9._+-]{0,31}", extension)
                is None
            ):
                raise RecipeError("extract %s has an invalid file extension" % rule_id)
        for boolean_name in ("case_sensitive", "flatten"):
            if boolean_name in source and not isinstance(source[boolean_name], bool):
                raise RecipeError(
                    "extract %s %s must be boolean" % (rule_id, boolean_name)
                )
        if "required" in rule and not isinstance(rule["required"], bool):
            raise RecipeError("extract %s required must be boolean" % rule_id)
        destination = rule.get("destination")
        if not isinstance(destination, str) or not destination:
            raise RecipeError("extract %s destination is required" % rule_id)
        allowed_destination_fields = (
            {"abi", "basename"}
            if kind in ("entry", "file", "entry_or_file", "container")
            else {"abi"}
        )
        validate_template_fields(
            destination,
            allowed_destination_fields,
            "extract %s destination" % rule_id,
        )
        if kind in ("entry", "file", "entry_or_file", "container"):
            validate_relative_path(
                destination.replace("{abi}", "ABI").replace("{basename}", "FILE"),
                "extract %s destination" % rule_id,
            )
        else:
            validate_relative_path(
                destination.replace("{abi}", "ABI"),
                "extract %s destination" % rule_id,
            )
        strip_prefix = source.get("strip_prefix")
        if strip_prefix is not None and not isinstance(strip_prefix, str):
            raise RecipeError("extract %s strip_prefix must be text" % rule_id)
        if strip_prefix is not None:
            validate_template_fields(
                strip_prefix, {"abi"}, "extract %s strip_prefix" % rule_id
            )
        if "split" in source:
            split = source["split"]
            if kind != "container":
                raise RecipeError("extract %s split is only valid for container" % rule_id)
            if not isinstance(split, str) or re.fullmatch(
                r"[A-Za-z0-9._-]{1,255}", split
            ) is None:
                raise RecipeError("extract %s split is invalid" % rule_id)
        validation = rule.get("validate", {})
        if not isinstance(validation, dict):
            raise RecipeError("extract %s validate must be an object" % rule_id)
        self._validate_validation(validation, "extract %s" % rule_id)
        # Um hook legitimo pode MUDAR o payload -- recomprimir textura, reduzir
        # audio -- e ate' aqui a mesma regra era cobrada antes e depois dele.
        # A receita entao precisava afrouxar para um intervalo que coubesse os
        # dois estados, e perdia a capacidade de reprovar um stage interrompido
        # no meio da transformacao. Com as duas fases separadas, cada lado pode
        # declarar tamanho e fingerprint EXATOS, e o estado intermediario nao
        # satisfaz nenhum dos dois.
        for phase_field in ("source_validate", "output_validate"):
            if phase_field not in rule:
                continue
            phase_validation = rule[phase_field]
            if not isinstance(phase_validation, dict):
                raise RecipeError("extract %s %s must be an object"
                                  % (rule_id, phase_field))
            self._validate_validation(phase_validation,
                                      "extract %s %s" % (rule_id, phase_field))
        if "mode" in rule:
            mode = rule["mode"]
            if not isinstance(mode, (str, int)) or isinstance(mode, bool):
                raise RecipeError("extract %s mode must be octal" % rule_id)
            try:
                numeric_mode = int(str(mode), 8)
            except ValueError:
                raise RecipeError("extract %s mode must be octal" % rule_id)
            if numeric_mode < 0 or numeric_mode > 0o777:
                raise RecipeError("extract %s mode is out of range" % rule_id)

    def _validate_validation(self, spec, label):
        for key in (
            "size",
            "min_size",
            "max_size",
            "exact_files",
            "min_files",
            "max_files",
            "exact_bytes",
            "min_bytes",
            "max_bytes",
            "exact_entries",
            "min_entries",
            "max_entries",
            "magic_offset",
        ):
            if key in spec and (
                not isinstance(spec[key], int) or isinstance(spec[key], bool) or spec[key] < 0
            ):
                raise RecipeError("%s %s must be a non-negative integer" % (label, key))
        for canonical, alias in (
            ("exact_files", "exact_entries"),
            ("min_files", "min_entries"),
            ("max_files", "max_entries"),
        ):
            if canonical in spec and alias in spec and spec[canonical] != spec[alias]:
                raise RecipeError(
                    "%s %s conflicts with %s" % (label, canonical, alias)
                )
        exact_count = spec.get("exact_files", spec.get("exact_entries"))
        minimum_count = spec.get("min_files", spec.get("min_entries"))
        maximum_count = spec.get("max_files", spec.get("max_entries"))
        if exact_count is not None and (
            (minimum_count is not None and exact_count < minimum_count)
            or (maximum_count is not None and exact_count > maximum_count)
        ):
            raise RecipeError("%s exact file count conflicts with its bounds" % label)
        if (
            minimum_count is not None
            and maximum_count is not None
            and minimum_count > maximum_count
        ):
            raise RecipeError("%s minimum file count exceeds maximum" % label)
        if "size" in spec and (
            ("min_size" in spec and spec["size"] < spec["min_size"])
            or ("max_size" in spec and spec["size"] > spec["max_size"])
        ):
            raise RecipeError("%s exact size conflicts with its bounds" % label)
        if (
            "min_size" in spec
            and "max_size" in spec
            and spec["min_size"] > spec["max_size"]
        ):
            raise RecipeError("%s minimum size exceeds maximum" % label)
        normalize_hash_list(spec.get("sha256"), "%s sha256" % label)
        normalize_crc_list(spec.get("crc32"), "%s crc32" % label)
        parse_magic(spec)
        expected_type = spec.get("type")
        if expected_type not in (None, "file", "tree", "directory"):
            raise RecipeError("%s type is unsupported" % label)
        fingerprint = spec.get("tree_fingerprint")
        if fingerprint is not None and (
            not isinstance(fingerprint, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint) is None
        ):
            raise RecipeError("%s tree_fingerprint must be SHA-256 hex" % label)
        if "elf_machine" in spec:
            machine = str(spec["elf_machine"]).lower()
            if machine != "{abi}" and machine not in ELF_MACHINES:
                raise RecipeError("%s elf_machine is unsupported" % label)
        required = spec.get("required_paths", [])
        if not isinstance(required, list):
            raise RecipeError("%s required_paths must be a list" % label)
        required_keys = set()
        for item in required:
            validate_relative_path(item, "%s required path" % label)
            key = portable_path_key(item)
            if key in required_keys:
                raise RecipeError("%s required_paths contains a collision" % label)
            required_keys.add(key)

    def _validate_output_check(self, check, label):
        if not isinstance(check, dict) or not isinstance(check.get("path"), str):
            raise RecipeError("%s item must contain a path" % label)
        validate_relative_path(
            check["path"].replace("{abi}", "ABI"), "%s path" % label
        )
        validate_template_fields(check["path"], {"abi"}, "%s path" % label)
        self._validate_validation(check, label)

    @property
    def mutable_paths(self):
        """P12: caminhos sob commit que o GUEST pode criar/alterar (saves
        gravados junto dos assets). Ficam FORA do selo de metadados."""
        return tuple(self.data.get("mutable", []))

    @property
    def identifier(self):
        return self.data["id"]

    @property
    def title(self):
        return self.data.get("title", self.identifier)

    @property
    def version(self):
        return str(self.data["version"])

    @property
    def marker(self):
        return self.data.get("marker", ".nxextract-%s.json" % self.identifier)

    @property
    def detail_log(self):
        return self.data.get("detail_log", DEFAULT_DETAIL_LOG)

    @property
    def terminal_result(self):
        return DEFAULT_TERMINAL_RESULT

    @property
    def input_config(self):
        value = self.data.get("input", {})
        if not isinstance(value, dict):
            raise RecipeError("input must be an object")
        return value

    def abi_order(self):
        values = self.data.get("abi_order")
        if values is None:
            machine = platform.machine().lower()
            if machine in ("aarch64", "arm64"):
                return ["arm64-v8a", "armeabi-v7a"]
            if machine.startswith("arm"):
                return ["armeabi-v7a", "armeabi"]
            if machine in ("x86_64", "amd64"):
                return ["x86_64", "x86"]
            return ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value for value in values
        ):
            raise RecipeError("abi_order must be a non-empty string list")
        return values


class Progress:
    def __init__(self, path=None, logger=None):
        self.path = os.path.abspath(os.fspath(path)) if path else None
        self.logger = logger
        self.state = 1
        self.phase = 0
        self.overall = 0
        self.phase_progress = 0
        self.done_bytes = 0
        self.total_bytes = 0
        self.message = "PREPARING"
        self.detail = ""
        self.last_write = 0.0
        self.last_tuple = None
        self.guard = None

    def set_guard(self, guard):
        self.guard = guard

    def update(
        self,
        phase=None,
        overall=None,
        phase_progress=None,
        done_bytes=None,
        total_bytes=None,
        message=None,
        detail=None,
        state=None,
        force=False,
    ):
        if self.guard is not None:
            self.guard()
        if phase is not None:
            self.phase = max(0, min(8, int(phase)))
        if overall is not None:
            self.overall = max(0, min(1000, int(overall)))
        if phase_progress is not None:
            self.phase_progress = max(0, min(1000, int(phase_progress)))
        if done_bytes is not None:
            self.done_bytes = max(0, int(done_bytes))
        if total_bytes is not None:
            self.total_bytes = max(0, int(total_bytes))
        if message is not None:
            self.message = " ".join(str(message).replace("\r", " ").replace("\n", " ").split())
        if detail is not None:
            self.detail = " ".join(str(detail).replace("\r", " ").replace("\n", " ").split())
        if state is not None:
            self.state = int(state)
        current = (
            self.state,
            self.phase,
            self.overall,
            self.phase_progress,
            self.done_bytes,
            self.total_bytes,
            self.message,
            self.detail,
        )
        now = time.monotonic()
        if not force and current == self.last_tuple:
            return
        if not force and now - self.last_write < 0.08:
            return
        self.last_tuple = current
        self.last_write = now
        if self.path:
            payload = (
                "%d %d 1000\n"
                "%s\n"
                "NXEXTRACT_V1 %d %d %d %d %d\n"
                "%s\n"
            ) % (
                self.state,
                self.overall,
                self.message or PHASES[self.phase],
                self.phase,
                self.overall,
                self.phase_progress,
                self.done_bytes,
                self.total_bytes,
                self.detail,
            )
            try:
                atomic_write(self.path, payload)
            except OSError:
                self.path = None

    def fail(self, message):
        self.update(state=2, message=message, force=True)

    def done(self, message="GAME DATA READY"):
        self.update(
            phase=8,
            overall=1000,
            phase_progress=1000,
            state=3,
            message=message,
            force=True,
        )


class Logger:
    """Compact milestone log plus a lossless opt-in detail stream."""

    def __init__(
        self,
        path=None,
        detail_path=None,
        detail_label=None,
        verbose=True,
        verbose_detail=False,
    ):
        self.path = path
        self.detail_path = detail_path
        self.detail_label = detail_label or (
            os.path.basename(detail_path) if detail_path else None
        )
        self.verbose = verbose
        self.verbose_detail = verbose_detail
        self.stream = None
        self.detail_stream = None
        self.repeated = {}
        self.closed = False
        self.compact_bytes = 0
        self.detail_bytes = 0
        self.compact_capped = False
        self.detail_rotations = 0
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            self.stream = open_private_text_append(path)
        if detail_path:
            try:
                os.makedirs(os.path.dirname(detail_path) or ".", exist_ok=True)
                self.detail_stream = open_private_text_append(detail_path)
            except BaseException:
                if self.stream:
                    self.stream.close()
                    self.stream = None
                raise

    @staticmethod
    def _line(message):
        return "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)

    def _cap_compact(self, size):
        """Return True while the compact log may still be written."""
        if self.compact_capped:
            return False
        if self.compact_bytes + size <= COMPACT_LOG_CEILING:
            self.compact_bytes += size
            return True
        # Say so on the way out, or the cap is indistinguishable from a
        # crash that stopped the run.
        self.compact_capped = True
        notice = self._line(
            "compact log reached its %d byte budget; the rest of this run is"
            " in %s only" % (COMPACT_LOG_CEILING, self.detail_label or "the"
                             " detail log")
        ) + "\n"
        try:
            self.stream.write(notice)
            self.stream.flush()
        except OSError:
            pass
        return False

    def _rotate_detail(self, size):
        """Keep the most recent window plus exactly one previous generation."""
        if self.detail_bytes + size <= DETAIL_LOG_CEILING:
            self.detail_bytes += size
            return
        try:
            self.detail_stream.flush()
            self.detail_stream.close()
            os.replace(self.detail_path, self.detail_path + ".prev")
            self.detail_stream = open_private_text_append(self.detail_path)
        except OSError:
            # A rotation the filesystem refuses must not take the log stream
            # down with it: keep writing where we already are.
            if self.detail_stream is None or self.detail_stream.closed:
                try:
                    self.detail_stream = open_private_text_append(
                        self.detail_path)
                except OSError:
                    self.detail_stream = None
            self.detail_bytes += size
            return
        self.detail_rotations += 1
        self.detail_bytes = size

    def _emit(self, message, compact, console):
        line = self._line(message)
        if console and self.verbose:
            print(line, flush=True)
        size = len(line.encode("utf-8", "replace")) + 1
        if compact and self.stream and self._cap_compact(size):
            self.stream.write(line + "\n")
        if self.detail_stream:
            self._rotate_detail(size)
        if self.detail_stream:
            self.detail_stream.write(line + "\n")

    def log(self, message):
        self._emit(message, compact=True, console=True)

    def detail(self, message):
        self._emit(
            message,
            compact=self.verbose_detail,
            console=self.verbose_detail,
        )

    def miss(self, category, message):
        """Keep the first miss visible and summarize repeats at the boundary."""
        record = self.repeated.setdefault(
            str(category), {"count": 0}
        )
        record["count"] += 1
        if record["count"] == 1:
            self.log(message)
        else:
            self.detail(message)

    def flush_repeated(self):
        for category in sorted(self.repeated):
            record = self.repeated[category]
            suppressed = record["count"] - 1
            if suppressed > 0:
                suffix = (
                    "; see %s" % self.detail_label
                    if self.detail_label
                    else ""
                )
                self.log(
                    "suppressed %d repeated %s miss(es)%s"
                    % (suppressed, category, suffix)
                )
        self.repeated.clear()

    def terminal(self, message):
        # Terminal cause is never compacted, even when its class was seen before.
        self.flush_repeated()
        self.log(message)

    def close(self):
        if self.closed:
            return
        self.flush_repeated()
        if self.stream:
            self.stream.close()
            self.stream = None
        if self.detail_stream:
            self.detail_stream.close()
            self.detail_stream = None
        self.closed = True


def sanitize_terminal_message(message):
    """Preserve the cause while removing URLs, host paths and package filenames."""
    value = " ".join(str(message).replace("\r", " ").replace("\n", " ").split())
    value = re.sub(r"(?i)\b(?:https?|ftp)://\S+", "<redacted-source>", value)
    value = re.sub(
        r"(?i)(?<![A-Za-z0-9_.-])[^\s,;:()]*\.(?:apk|apkm|apks|xapk|obb|zip)\b",
        "<container>",
        value,
    )
    value = re.sub(r"(?<![A-Za-z0-9_.-])/(?:[^\s,;:()]+/)*[^\s,;:()]*", "<path>", value)
    return value[:512] or "unspecified failure"


def _result_items(plan=None, marker=None):
    if plan is not None:
        return [
            {
                "rule": item.rule_id,
                "size": int(item.size),
            }
            for item in plan.items
        ]
    if marker is not None:
        return [
            {"rule": item["rule"], "size": int(item["size"])}
            for item in marker.get("items", [])
            if isinstance(item, dict)
            and isinstance(item.get("rule"), str)
            and isinstance(item.get("size"), int)
            and not isinstance(item.get("size"), bool)
            and item.get("size") >= 0
        ]
    return []


def _critical_payload_summary(recipe, items):
    totals = {}
    for item in items:
        record = totals.setdefault(item["rule"], {"items": 0, "bytes": 0})
        record["items"] += 1
        record["bytes"] += item["size"]
    result = []
    for rule in recipe.data["extract"]:
        if not rule.get("required", True):
            continue
        totals_for_rule = totals.get(rule["id"], {"items": 0, "bytes": 0})
        result.append(
            {
                "id": rule["id"],
                "items": totals_for_rule["items"],
                "bytes": totals_for_rule["bytes"],
            }
        )
    return result


def _terminal_selection(recipe, plan=None, marker=None):
    if plan is not None:
        source_kind = plan.group.source_kind
        package_id = plan.group.package
        abi = plan.abi
        fingerprint = plan.fingerprint
    elif marker is not None:
        source_kind = marker.get("source_kind")
        package_id = marker.get("package_id")
        abi = marker.get("abi")
        fingerprint = marker.get("plan_fingerprint")
    else:
        source_kind = None
        package_id = None
        abi = None
        fingerprint = None
    if source_kind not in ("apk-set", "bundle", "companion", "existing"):
        source_kind = None
    if (
        not isinstance(package_id, str)
        or len(package_id) > 255
        or re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id) is None
    ):
        package_id = None
    if not isinstance(abi, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", abi) is None:
        abi = None
    identity = None
    if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        identity = sha256_bytes(
            canonical_json(
                {
                    "abi": abi,
                    "fingerprint": fingerprint,
                    "kind": source_kind,
                    "package_id": package_id,
                    "recipe_digest": recipe.digest,
                }
            )
        )
    return {
        "abi": abi,
        "package_id": package_id,
        "container": {
            "kind": source_kind,
            "identity": identity,
        },
    }


def terminal_result_payload(
    recipe,
    progress,
    outcome,
    code,
    summary_log,
    detail_log,
    started_monotonic,
    plan=None,
    marker=None,
    validated=False,
    error=None,
    ui=None,
):
    phase = max(0, min(8, int(progress.phase)))
    items = _result_items(plan=plan, marker=marker) if validated else []
    selection = _terminal_selection(recipe, plan=plan, marker=marker)
    ui_receipt = (
        ui.terminal_receipt()
        if ui is not None
        else {
            "mode": "disabled",
            "renderer": None,
            "fallback_reason": None,
        }
    )
    payload = {
        "schema": TERMINAL_RESULT_SCHEMA,
        "schema_version": TERMINAL_RESULT_SCHEMA_VERSION,
        "nxextract_version": NXEXTRACT_VERSION,
        "outcome": outcome,
        "code": code,
        "final_phase": {
            "index": phase,
            "id": PHASE_IDS[phase],
            "label": PHASES[phase],
        },
        "recipe": {
            "id": recipe.identifier,
            "version": recipe.version,
            "digest": recipe.digest,
        },
        "package_id": selection["package_id"],
        "abi": selection["abi"],
        "container": selection["container"],
        # P11.7: como a setup UI terminou. "visible" = renderer atestado;
        # "headless-fallback" = renderer nao abriu e a extracao seguiu sem a
        # barra visual (fallback_reason nomeia o motivo, com a ultima linha do
        # log da UI); "disabled" = UI desligada/opcional ausente.
        "ui": ui_receipt,
        "validated": {
            "items": len(items),
            "bytes": sum(item["size"] for item in items),
            "critical_payloads": _critical_payload_summary(recipe, items),
        },
        "logs": {
            "summary": summary_log,
            "detail": detail_log,
        },
        "duration_ms": max(
            0, int((time.monotonic() - started_monotonic) * 1000)
        ),
        "completed_unix": int(time.time()),
        "error": None,
    }
    if error is not None:
        payload["error"] = {
            "class": type(error).__name__,
            "message": sanitize_terminal_message(error),
        }
    return payload


def publish_terminal_result(path, payload):
    """Publish a complete result; a partial JSON file is never observable."""
    atomic_write_json(path, payload, required_directory_sync=True)


def _decode_length8(data, offset):
    first = data[offset]
    offset += 1
    if first & 0x80:
        second = data[offset]
        offset += 1
        return ((first & 0x7F) << 8) | second, offset
    return first, offset


def _decode_length16(data, offset):
    first = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if first & 0x8000:
        second = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        return ((first & 0x7FFF) << 16) | second, offset
    return first, offset


class AndroidStringPool:
    UTF8_FLAG = 0x100

    def __init__(self, chunk):
        if len(chunk) < 28:
            raise ValueError("truncated Android string pool")
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", chunk, 0)
        if chunk_type != 0x0001 or chunk_size > len(chunk) or header_size < 28:
            raise ValueError("invalid Android string pool")
        count, _styles, flags, strings_start, _styles_start = struct.unpack_from(
            "<IIIII", chunk, 8
        )
        if count > 1_000_000 or header_size + count * 4 > chunk_size:
            raise ValueError("unreasonable Android string pool")
        offsets = struct.unpack_from("<%dI" % count, chunk, header_size) if count else ()
        self.strings = []
        utf8 = bool(flags & self.UTF8_FLAG)
        for item in offsets:
            position = strings_start + item
            if position >= chunk_size:
                raise ValueError("Android string offset out of range")
            if utf8:
                _utf16_length, position = _decode_length8(chunk, position)
                byte_length, position = _decode_length8(chunk, position)
                end = position + byte_length
                if end > chunk_size:
                    raise ValueError("truncated Android UTF-8 string")
                text = chunk[position:end].decode("utf-8", "strict")
            else:
                char_length, position = _decode_length16(chunk, position)
                end = position + char_length * 2
                if end > chunk_size:
                    raise ValueError("truncated Android UTF-16 string")
                text = chunk[position:end].decode("utf-16le", "strict")
            self.strings.append(text)

    def get(self, index):
        if index == 0xFFFFFFFF:
            return None
        if index < 0 or index >= len(self.strings):
            raise ValueError("Android string index out of range")
        return self.strings[index]


def parse_android_manifest(data):
    """Return (package, split) from binary AXML or plain XML."""
    stripped = data.lstrip()
    if stripped.startswith(b"<"):
        import xml.etree.ElementTree as element_tree

        root = element_tree.fromstring(data)
        package_name = root.attrib.get("package")
        split = root.attrib.get("split", "")
        if not package_name:
            raise ValueError("plain Android manifest has no package")
        return package_name, split

    if len(data) < 8:
        raise ValueError("truncated Android manifest")
    xml_type, xml_header, xml_size = struct.unpack_from("<HHI", data, 0)
    if xml_type != 0x0003 or xml_header < 8 or xml_size > len(data):
        raise ValueError("not an Android binary XML document")
    pool = None
    offset = xml_header
    while offset + 8 <= xml_size:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if header_size < 8 or chunk_size < header_size or offset + chunk_size > xml_size:
            raise ValueError("invalid Android XML chunk")
        chunk = data[offset : offset + chunk_size]
        if chunk_type == 0x0001:
            pool = AndroidStringPool(chunk)
        elif chunk_type == 0x0102 and pool is not None:
            if header_size < 16 or len(chunk) < 36:
                raise ValueError("truncated Android start element")
            name_index = struct.unpack_from("<I", chunk, 20)[0]
            name = pool.get(name_index)
            if name != "manifest":
                offset += chunk_size
                continue
            attribute_start, attribute_size, attribute_count = struct.unpack_from(
                "<HHH", chunk, 24
            )
            if attribute_size < 20 or attribute_count > 4096:
                raise ValueError("invalid Android manifest attributes")
            base = 16 + attribute_start
            package_name = None
            split = ""
            for index in range(attribute_count):
                position = base + index * attribute_size
                if position + 20 > len(chunk):
                    raise ValueError("truncated Android manifest attribute")
                _namespace, attribute_name, raw_value = struct.unpack_from(
                    "<III", chunk, position
                )
                value_type = chunk[position + 15]
                value_data = struct.unpack_from("<I", chunk, position + 16)[0]
                key = pool.get(attribute_name)
                if raw_value != 0xFFFFFFFF:
                    value = pool.get(raw_value)
                elif value_type == 0x03:
                    value = pool.get(value_data)
                else:
                    value = str(value_data)
                if key == "package":
                    package_name = value
                elif key == "split":
                    split = value or ""
            if not package_name:
                raise ValueError("Android manifest has no package")
            return package_name, split
        offset += chunk_size
    raise ValueError("Android manifest root was not found")


class Archive:
    def __init__(self, path, kind, parent=None, label=None):
        original = os.path.abspath(os.fspath(path))
        if not is_regular_file(original):
            raise SourceError("archive is missing, linked or not regular: %s" % path)
        self.path = os.path.realpath(original)
        self.kind = kind
        self.parent = os.path.realpath(parent) if parent else self.path
        self.label = label or os.path.basename(self.parent)
        self.zip = None
        self.members = {}
        self.portable_collisions = {}
        self.package = None
        self.split = ""
        self._open()

    def _open(self):
        if not is_regular_file(self.path):
            raise SourceError("archive is missing, linked or not regular: %s" % self.path)
        try:
            self.zip = zipfile.ZipFile(self.path, "r")
            exact = set()
            portable_components = {}
            component_types = {}
            for info in self.zip.infolist():
                name = safe_zip_name(info.filename, info.is_dir())
                if not name:
                    continue
                if name in exact:
                    raise SourceError(
                        "duplicate ZIP entry in %s: %s" % (self.label, name)
                    )
                exact.add(name)
                parts = name.split("/")
                for index in range(1, len(parts) + 1):
                    prefix = "/".join(parts[:index])
                    key = portable_path_key(prefix)
                    previous = portable_components.get(key)
                    if previous is not None and previous != prefix:
                        # Real Android APKs routinely carry case-colliding
                        # obfuscated resources (res/9N.9.png vs res/9n.9.png).
                        # Refusing the whole archive here rejected legitimate
                        # builds whose colliding members are never extracted,
                        # so the collision is recorded and only enforced over
                        # the members a recipe actually selects.
                        self.portable_collisions.setdefault(key, (previous, prefix))
                    portable_components[key] = prefix
                    object_type = (
                        "directory"
                        if index < len(parts) or info.is_dir()
                        else "file"
                    )
                    previous_type = component_types.get(key)
                    if previous_type is not None and previous_type != object_type:
                        raise SourceError(
                            "ZIP file/directory collision in %s: %s"
                            % (self.label, prefix)
                        )
                    component_types[key] = object_type
                if info.is_dir():
                    continue
                if info.flag_bits & 1:
                    raise SourceError(
                        "encrypted ZIP member is unsupported: %s in %s"
                        % (info.filename, self.label)
                    )
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if stat.S_ISLNK(mode) or file_type not in (0, stat.S_IFREG):
                    raise SourceError(
                        "linked or special ZIP member is unsupported: %s in %s"
                        % (info.filename, self.label)
                    )
                self.members[name] = info
            manifest = self.members.get("AndroidManifest.xml")
            if manifest is not None:
                try:
                    with self.zip.open(manifest, "r") as stream:
                        data = stream.read(4 * 1024 * 1024 + 1)
                    if len(data) > 4 * 1024 * 1024:
                        raise ValueError("Android manifest is unreasonably large")
                    self.package, self.split = parse_android_manifest(data)
                except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
                    raise SourceError(
                        "cannot identify Android manifest in %s: %s"
                        % (self.label, error)
                    )
        except Exception:
            self.close()
            raise

    def open_member(self, info):
        if info.flag_bits & 1:
            raise SourceError(
                "encrypted ZIP member is unsupported: %s in %s"
                % (info.filename, self.label)
            )
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise SourceError(
                "symbolic-link ZIP member is unsupported: %s in %s"
                % (info.filename, self.label)
            )
        file_type = stat.S_IFMT(mode)
        if file_type not in (0, stat.S_IFREG):
            raise SourceError(
                "special-file ZIP member is unsupported: %s in %s"
                % (info.filename, self.label)
            )
        return self.zip.open(info, "r")

    def close(self):
        if self.zip is not None:
            try:
                self.zip.close()
            except Exception:
                pass
            self.zip = None


class LooseFile:
    def __init__(self, path):
        original = os.path.abspath(os.fspath(path))
        if not is_regular_file(original):
            raise SourceError("input is missing, linked or not regular: %s" % path)
        self.path = os.path.realpath(original)
        self.label = os.path.basename(path)


class CandidateGroup:
    def __init__(self, label, archives, loose, package=None, source_kind="loose"):
        self.label = label
        self.archives = archives
        self.loose = loose
        self.package = package
        self.source_kind = source_kind

    def description(self):
        if self.package:
            return "%s (package %s)" % (self.label, self.package)
        return self.label


class Discovery:
    def __init__(self):
        self.apks = []
        self.bundles = []
        self.generic_archives = []
        self.loose = []
        self.skipped = []

    def all_paths(self):
        return self.apks + self.bundles + self.generic_archives + self.loose


def zip_classification(path):
    try:
        with zipfile.ZipFile(path, "r") as archive:
            regular = [info for info in archive.infolist() if not info.is_dir()]
            names = {info.filename for info in regular}
            if "AndroidManifest.xml" in names:
                return "apk"
            inner_apks = [
                info
                for info in regular
                if PurePosixPath(info.filename).suffix.lower() == ".apk"
            ]
            if inner_apks:
                return "bundle"
            return "archive"
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        return None


def discover_inputs(recipe, game_dir, explicit_inputs, logger):
    config = recipe.input_config
    extensions = config.get("extensions", list(DEFAULT_EXTENSIONS))
    if not isinstance(extensions, list) or not all(
        isinstance(item, str) and item.startswith(".") for item in extensions
    ):
        raise RecipeError("input.extensions must be a list of .extensions")
    extensions = {item.lower() for item in extensions}
    for rule in recipe.data["extract"]:
        source = rule["source"]
        for item in source.get("file_extensions", []):
            if not isinstance(item, str) or not item.startswith("."):
                raise RecipeError("file_extensions values must begin with a dot")
            extensions.add(item.lower())
    maximum = int(config.get("max_files", 128))
    if maximum < 1 or maximum > 4096:
        raise RecipeError("input.max_files must be between 1 and 4096")
    paths = []
    if explicit_inputs:
        for value in explicit_inputs:
            original = os.path.abspath(value)
            if not is_regular_file(original):
                raise SourceError("explicit input is not a regular file: %s" % value)
            candidate = os.path.realpath(original)
            paths.append(candidate)
    else:
        search_dirs = config.get("search_dirs", ["gamedata", "."])
        if not isinstance(search_dirs, list) or not search_dirs:
            raise RecipeError("input.search_dirs must be a non-empty list")
        prefer_first = bool(config.get("prefer_first_nonempty", True))
        sniff_primary = bool(config.get("sniff_all_in_primary", True))
        for directory_index, relative in enumerate(search_dirs):
            if relative == ".":
                directory = game_dir
            else:
                validate_relative_path(relative, "input search directory")
                ensure_no_symlink_parents(
                    game_dir, relative.rstrip("/") + "/.nxextract-scan"
                )
                directory = safe_join(game_dir, relative, "input search directory")
            if not os.path.isdir(directory) or os.path.islink(directory):
                continue
            found_here = []
            for name in sorted(os.listdir(directory), key=portable_path_key):
                candidate = os.path.join(directory, name)
                if not is_regular_file(candidate):
                    continue
                suffix = Path(name).suffix.lower()
                if suffix in extensions or (directory_index == 0 and sniff_primary):
                    found_here.append(os.path.realpath(candidate))
            if found_here:
                paths.extend(found_here)
                if prefer_first:
                    break
    unique = []
    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    if len(unique) > maximum:
        raise SourceError(
            "too many candidate input files (%d; maximum %d)" % (len(unique), maximum)
        )

    result = Discovery()
    for path in unique:
        classification = zip_classification(path) if zipfile.is_zipfile(path) else None
        if classification == "apk":
            result.apks.append(path)
        elif classification == "bundle":
            result.bundles.append(path)
        elif classification == "archive":
            result.generic_archives.append(path)
            if Path(path).suffix.lower() == ".obb":
                # Android OBBs are frequently plain ZIPs (Aspyr, Gameloft,
                # Rockstar). The archive itself is the payload: keep it as a
                # loose-file candidate too, so `file`/`entry_or_file` rules can
                # select the OBB directly while `entry` rules may still look
                # inside it.
                result.loose.append(path)
        else:
            suffix = Path(path).suffix.lower()
            if suffix in extensions:
                result.loose.append(path)
            else:
                result.skipped.append(path)
    logger.log(
        "content scan: %d APK, %d bundle, %d companion archive, %d loose file"
        % (
            len(result.apks),
            len(result.bundles),
            len(result.generic_archives),
            len(result.loose),
        )
    )
    return result


def _bundle_cache_token(path):
    info = os.stat(path, follow_symlinks=False)
    identity = "%s\0%d\0%d" % (
        os.path.realpath(path),
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )
    return sha256_bytes(identity.encode("utf-8"))[:20]


def _zip_member_cache_valid(info, destination):
    if not is_private_regular_file(destination):
        return False
    try:
        return (
            file_size(destination) == info.file_size
            and file_crc32(destination) == info.CRC
        )
    except OSError:
        return False


def _copy_zip_member_resume(archive, info, destination, max_member_bytes):
    if info.file_size <= 0 or info.file_size > max_member_bytes:
        raise SourceError(
            "inner APK has unsafe size %d: %s" % (info.file_size, info.filename)
        )
    if _zip_member_cache_valid(info, destination):
        return
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    temporary = destination + ".part"
    try:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        value = 0
        written = 0
        with archive.open_member(info) as source, open(temporary, "xb") as output:
            while True:
                block = source.read(CHUNK_SIZE)
                if not block:
                    break
                output.write(block)
                value = binascii.crc32(block, value)
                written += len(block)
            output.flush()
            os.fsync(output.fileno())
        if written != info.file_size or (value & 0xFFFFFFFF) != info.CRC:
            raise SourceError("inner APK failed size/CRC validation: %s" % info.filename)
        os.replace(temporary, destination)
        fsync_directory(os.path.dirname(destination))
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _check_free_space(path, required, label):
    available = shutil.disk_usage(path).free
    if available < required:
        raise SourceError(
            "not enough free space for %s: need %s, have %s"
            % (label, human_bytes(required), human_bytes(available))
        )


def build_candidate_groups(recipe, discovery, workspace, logger, progress):
    config = recipe.input_config
    max_bundle_apks = int(config.get("max_bundle_apks", 128))
    max_member_bytes = int(config.get("max_member_bytes", 8 * 1024**3))
    max_bundle_bytes = int(config.get("max_bundle_bytes", 16 * 1024**3))
    if max_bundle_apks < 1 or max_bundle_apks > 4096:
        raise RecipeError("input.max_bundle_apks is out of range")
    if max_member_bytes < 1 or max_bundle_bytes < 1:
        raise RecipeError("input bundle byte limits must be positive")
    safety = int(recipe.data.get("space", {}).get("safety_bytes", DEFAULT_SAFETY_BYTES))
    cache_root = os.path.join(workspace, "source-cache")
    _ensure_real_directory(cache_root, "source cache")
    loose = [LooseFile(path) for path in discovery.loose]
    generic = [
        Archive(path, "bundle", label=os.path.basename(path))
        for path in discovery.generic_archives
    ]
    groups = []
    opened = list(generic)

    for bundle_index, path in enumerate(discovery.bundles):
        progress.update(
            phase=2,
            overall=80,
            phase_progress=0,
            message="PREPARING APK BUNDLE",
            detail=os.path.basename(path),
            force=True,
        )
        outer = Archive(path, "bundle", label=os.path.basename(path))
        opened.append(outer)
        members = [
            info
            for name, info in outer.members.items()
            if PurePosixPath(name).suffix.lower() == ".apk"
        ]
        if not members:
            raise SourceError("bundle contains no APK members: %s" % outer.label)
        if len(members) > max_bundle_apks:
            raise SourceError(
                "bundle contains too many APK members (%d): %s"
                % (len(members), outer.label)
            )
        expanded_bytes = sum(info.file_size for info in members)
        if expanded_bytes > max_bundle_bytes:
            raise SourceError(
                "bundle APK payload exceeds safety limit: %s" % outer.label
            )
        bundle_cache = os.path.join(cache_root, "bundle-" + _bundle_cache_token(path))
        _ensure_real_directory(bundle_cache, "bundle source cache")
        cache_destinations = []
        missing = 0
        for member_index, info in enumerate(members):
            token = sha256_bytes(info.filename.encode("utf-8"))[:12]
            destination = os.path.join(
                bundle_cache, "%03d-%s.apk" % (member_index, token)
            )
            cache_destinations.append((info, destination))
            if not _zip_member_cache_valid(info, destination):
                missing += info.file_size
        _check_free_space(workspace, missing + safety, "APK bundle expansion")
        inner_archives = []
        for info, destination in cache_destinations:
            _copy_zip_member_resume(outer, info, destination, max_member_bytes)
            inner = Archive(
                destination,
                "apk",
                parent=path,
                label="%s:%s" % (outer.label, info.filename),
            )
            if not inner.package:
                raise SourceError("inner APK has no Android package: %s" % inner.label)
            inner_archives.append(inner)
            opened.append(inner)
        packages = sorted({item.package for item in inner_archives if item.package})
        package_name = packages[0] if len(packages) == 1 else None
        if len(packages) > 1:
            raise SourceError(
                "bundle mixes multiple Android packages: %s" % ", ".join(packages)
            )
        groups.append(
            CandidateGroup(
                outer.label,
                inner_archives + [outer] + generic,
                loose,
                package_name,
                "bundle",
            )
        )
        logger.log(
            "bundle %s: %d APK(s), package=%s"
            % (outer.label, len(inner_archives), package_name or "unknown")
        )

    direct_by_package = {}
    unknown_direct = []
    for path in discovery.apks:
        archive = Archive(path, "apk", label=os.path.basename(path))
        opened.append(archive)
        if archive.package:
            direct_by_package.setdefault(archive.package, []).append(archive)
        else:
            unknown_direct.append(archive)
    for package_name, archives in sorted(direct_by_package.items()):
        label = "loose APK set (%s)" % package_name
        groups.append(
            CandidateGroup(
                label,
                archives + generic,
                loose,
                package_name,
                "apk-set",
            )
        )
        logger.log("APK set %s: %d split(s)" % (package_name, len(archives)))
    if unknown_direct:
        groups.append(
            CandidateGroup(
                "unidentified loose APK set",
                unknown_direct + generic,
                loose,
                None,
                "apk-set",
            )
        )
    if not groups and (generic or loose):
        groups.append(
            CandidateGroup("companion data", generic, loose, None, "companion")
        )
    if not groups:
        for archive in opened:
            archive.close()
        raise SourceError(
            "no game container was found in gamedata/ or in the port folder. "
            "Put the game file you own inside the port's gamedata/ folder "
            "(create the folder if it does not exist) and launch again; "
            "accepted files: .apk .apkm .apks .xapk .zip .obb"
        )
    wanted = config.get("packages")
    if wanted:
        if not isinstance(wanted, list) or not all(
            isinstance(item, str) and item for item in wanted
        ):
            raise RecipeError("input.packages must be a non-empty string list")
        allowed = set(wanted)
        # Um pacote com package desconhecido (APK sem manifest legivel) segue
        # candidato: quem decide e' a validacao de conteudo, nao a ausencia de
        # metadado. O que se recusa aqui e' o pacote de OUTRO aplicativo.
        kept = [
            group for group in groups
            if group.package is None or group.package in allowed
        ]
        refused = [group for group in groups if group not in kept]
        for group in refused:
            logger.log(
                "ignoring %s: package %s is not accepted by this recipe (%s)"
                % (group.label, group.package, ", ".join(sorted(allowed)))
            )
        if not kept:
            for archive in opened:
                archive.close()
            raise SourceError(
                "the files in gamedata/ belong to %s, and this port only accepts "
                "%s"
                % (
                    ", ".join(sorted({g.package for g in refused if g.package}))
                    or "an unknown application",
                    ", ".join(sorted(allowed)),
                )
            )
        groups = kept
    return groups, opened


class SourceItem:
    def __init__(self, rule_id, destination, archive=None, info=None, loose=None):
        self.rule_id = rule_id
        self.destination = destination
        self.archive = archive
        self.info = info
        self.loose = loose
        if info is not None:
            self.size = info.file_size
            self.crc = info.CRC
            self.source_name = info.filename
            self.source_label = archive.label
        else:
            self.size = file_size(loose.path)
            self.crc = None
            self.source_name = loose.label
            self.source_label = loose.label

    def identity(self):
        return (
            self.rule_id,
            portable_path_key(self.destination),
            self.size,
            self.crc,
            self.source_name,
        )


class Plan:
    def __init__(self, group, abi, items, commit_paths,
                 compatibility_result=None):
        self.group = group
        self.abi = abi
        self.items = items
        self.commit_paths = commit_paths
        self.compatibility_result = compatibility_result or {
            "schema": COMPATIBILITY_RESULT_SCHEMA,
            "schema_version": COMPATIBILITY_RESULT_SCHEMA_VERSION,
            "mode": "source",
            "abi": abi,
            "members": [],
            "patch_selections": [],
        }
        fingerprint = {
            "items": [
                (item.rule_id, item.destination, item.size, item.crc)
                for item in sorted(
                    items,
                    key=lambda value: portable_path_key(value.destination),
                )
            ],
            "compatibility": self.compatibility_result,
        }
        self.fingerprint = sha256_bytes(canonical_json(fingerprint))

    @property
    def total_bytes(self):
        return sum(item.size for item in self.items)


def template_value(value, abi, basename=None):
    mapping = {
        "abi": abi,
        "basename": basename or "",
    }
    try:
        return value.format(**mapping)
    except (KeyError, ValueError) as error:
        raise RecipeError("invalid template %r: %s" % (value, error))


def member_matches(name, pattern, case_sensitive=True):
    if case_sensitive:
        return fnmatch.fnmatchcase(name, pattern)
    return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())


def _read_magic_from_member(archive, info, offset, length):
    with archive.open_member(info) as stream:
        if offset:
            remaining = offset
            while remaining:
                block = stream.read(min(CHUNK_SIZE, remaining))
                if not block:
                    return b""
                remaining -= len(block)
        return stream.read(length)


def _sha256_member(archive, info):
    digest = hashlib.sha256()
    with archive.open_member(info) as stream:
        while True:
            block = stream.read(CHUNK_SIZE)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _elf_machine_from_header(header):
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    if header[5] == 1:
        return struct.unpack_from("<H", header, 18)[0]
    if header[5] == 2:
        return struct.unpack_from(">H", header, 18)[0]
    return None


def _expected_elf_machine(spec, abi):
    machine = str(spec["elf_machine"]).lower()
    if machine == "{abi}":
        if not abi:
            raise RecipeError("elf_machine {abi} requires a resolved ABI")
        machine = str(abi).lower()
    try:
        return ELF_MACHINES[machine]
    except KeyError:
        raise RecipeError("elf_machine is unsupported for ABI %s" % machine)


def validate_member_candidate(archive, info, spec, abi=None):
    if not _size_valid(info.file_size, spec):
        return False
    crc_values = normalize_crc_list(spec.get("crc32"), "crc32")
    if crc_values and info.CRC not in crc_values:
        return False
    magic = parse_magic(spec)
    offset = int(spec.get("magic_offset", 0))
    if magic is not None:
        try:
            if _read_magic_from_member(archive, info, offset, len(magic)) != magic:
                return False
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return False
    if "elf_machine" in spec:
        try:
            header = _read_magic_from_member(archive, info, 0, 64)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return False
        expected = _expected_elf_machine(spec, abi)
        if _elf_machine_from_header(header) != expected:
            return False
    hashes = normalize_hash_list(spec.get("sha256"), "sha256")
    if hashes:
        try:
            if _sha256_member(archive, info) not in hashes:
                return False
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return False
    return True


def validate_loose_candidate(loose, spec, abi=None):
    try:
        size = file_size(loose.path)
    except OSError:
        return False
    if not _size_valid(size, spec):
        return False
    magic = parse_magic(spec)
    offset = int(spec.get("magic_offset", 0))
    if magic is not None:
        try:
            with open(loose.path, "rb") as stream:
                stream.seek(offset)
                if stream.read(len(magic)) != magic:
                    return False
        except OSError:
            return False
    if "elf_machine" in spec:
        try:
            with open(loose.path, "rb") as stream:
                header = stream.read(64)
        except OSError:
            return False
        expected = _expected_elf_machine(spec, abi)
        if _elf_machine_from_header(header) != expected:
            return False
    crc_values = normalize_crc_list(spec.get("crc32"), "crc32")
    if crc_values and file_crc32(loose.path) not in crc_values:
        return False
    hashes = normalize_hash_list(spec.get("sha256"), "sha256")
    if hashes and file_sha256(loose.path) not in hashes:
        return False
    return True


def _size_valid(size, spec):
    if "size" in spec and size != spec["size"]:
        return False
    if "min_size" in spec and size < spec["min_size"]:
        return False
    if "max_size" in spec and size > spec["max_size"]:
        return False
    return True


def validate_summary(count, total, spec):
    exact_count = spec.get("exact_files", spec.get("exact_entries"))
    minimum_count = spec.get("min_files", spec.get("min_entries"))
    maximum_count = spec.get("max_files", spec.get("max_entries"))
    if exact_count is not None and count != exact_count:
        return False
    if minimum_count is not None and count < minimum_count:
        return False
    if maximum_count is not None and count > maximum_count:
        return False
    if "exact_bytes" in spec and total != spec["exact_bytes"]:
        return False
    if "min_bytes" in spec and total < spec["min_bytes"]:
        return False
    if "max_bytes" in spec and total > spec["max_bytes"]:
        return False
    return True


def _source_scopes(source):
    scopes = source.get("scopes", ["apk", "bundle"])
    if not isinstance(scopes, list) or not all(
        item in ("apk", "bundle") for item in scopes
    ):
        raise RecipeError("source scopes must contain apk and/or bundle")
    return scopes


def _assert_portable_selection(matches):
    """Enforce case-insensitive path safety over the SELECTED members only.

    An extracted tree must be writable on a case-insensitive card (exFAT/FAT),
    so two selected members may not collapse to the same portable path.  What
    the rest of the archive contains is irrelevant: it is never written.
    """
    seen = {}
    for archive, _info, name in matches:
        parts = name.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            key = (id(archive), portable_path_key(prefix))
            previous = seen.get(key)
            if previous is not None and previous != prefix:
                raise SourceError(
                    "non-portable ZIP path collision in %s: %s / %s"
                    % (archive.label, previous, prefix)
                )
            seen[key] = prefix


def _candidate_members(group, source, abi):
    patterns = [template_value(value, abi) for value in source.get("patterns", ["*"])]
    scopes = _source_scopes(source)
    case_sensitive = bool(source.get("case_sensitive", True))
    by_pattern = []
    for pattern in patterns:
        matches = []
        for archive in group.archives:
            if archive.kind not in scopes:
                continue
            for name, info in archive.members.items():
                if member_matches(name, pattern, case_sensitive):
                    matches.append((archive, info, name))
        _assert_portable_selection(matches)
        by_pattern.append((pattern, matches))
    return by_pattern


def _candidate_loose(group, source, abi):
    patterns = [template_value(value, abi) for value in source.get("patterns", ["*"])]
    case_sensitive = bool(source.get("case_sensitive", False))
    extensions = source.get("file_extensions", [])
    extensions = {item.lower() for item in extensions}
    matches = []
    for loose in group.loose:
        if extensions and Path(loose.path).suffix.lower() not in extensions:
            continue
        name = loose.label
        if any(member_matches(name, pattern, case_sensitive) for pattern in patterns):
            matches.append(loose)
    return matches


def _candidate_containers(group, source, abi):
    """O APK selecionado, ele mesmo, como arquivo.

    Existe porque ha' jogos cujo payload NAO e' um subconjunto de membros: o
    proprio APK e' o dado que o port abre em tempo de execucao (Cocos2d-x lendo
    os recursos por minizip, por exemplo). Sem isto, a unica saida seria
    extrair a arvore inteira e reempacota-la, ocupando o dobro do cartao.

    Por padrao seleciona o APK BASE (o que carrega os assets do app); um split
    especifico pode ser pedido por `split`.
    """
    # O padrao aqui e' `apk` e nao `apk+bundle`: o container e' o pacote do app.
    # O .xapk que o embrulha tambem e' um zip sem split, e entraria como segundo
    # candidato -- a recusa apareceria como "ambiguo", que nao explica nada.
    scopes = _source_scopes(dict(source, scopes=source.get("scopes", ["apk"])))
    wanted = source.get("split")
    patterns = [template_value(value, abi) for value in source.get("patterns", ["*"])]
    case_sensitive = bool(source.get("case_sensitive", False))
    found = []
    for archive in group.archives:
        if archive.kind not in scopes:
            continue
        split = archive.split or ""
        if wanted is None:
            if split:
                continue
        elif split != wanted:
            continue
        if not any(
            member_matches(archive.label, pattern, case_sensitive)
            for pattern in patterns
        ):
            continue
        found.append(LooseFile(archive.path))
    return found


def source_validation(rule):
    """A regra a cobrar do payload RECEM-EXTRAIDO, antes de qualquer hook."""
    return rule.get("source_validate", rule.get("validate", {}))


def output_validation(rule):
    """A regra a cobrar do resultado, DEPOIS dos hooks.

    Uma receita que nao usa os campos novos se comporta exatamente como antes:
    os dois lados caem no mesmo `validate`.
    """
    return rule.get("output_validate", rule.get("validate", {}))


def _choose_one(rule, group, abi):
    source = rule["source"]
    spec = source_validation(rule)
    candidates = []
    rejected = 0
    rejected_example = None
    if source["kind"] in ("entry", "entry_or_file"):
        for _pattern, matches in _candidate_members(group, source, abi):
            valid = [
                (archive, info, name)
                for archive, info, name in matches
                if validate_member_candidate(archive, info, spec, abi)
            ]
            invalid = [item for item in matches if item not in valid]
            rejected += len(invalid)
            if invalid and rejected_example is None:
                archive, _info, name = invalid[0]
                rejected_example = "%s:%s" % (archive.label, name)
            if valid:
                candidates.extend(valid)
                break
    loose_candidates = []
    if source["kind"] == "container":
        container_all = _candidate_containers(group, source, abi)
        loose_candidates = [
            item for item in container_all if validate_loose_candidate(item, spec, abi)
        ]
        container_invalid = [item for item in container_all if item not in loose_candidates]
        rejected += len(container_invalid)
        if container_invalid and rejected_example is None:
            rejected_example = container_invalid[0].label
    if source["kind"] in ("file", "entry_or_file"):
        loose_all = _candidate_loose(group, source, abi)
        loose_candidates = [
            loose
            for loose in loose_all
            if validate_loose_candidate(loose, spec, abi)
        ]
        loose_invalid = [item for item in loose_all if item not in loose_candidates]
        rejected += len(loose_invalid)
        if loose_invalid and rejected_example is None:
            rejected_example = loose_invalid[0].label
    identities = {}
    for archive, info, name in candidates:
        key = (info.file_size, info.CRC)
        identities.setdefault(key, []).append((archive, info, name))
    for loose in loose_candidates:
        key = (file_size(loose.path), file_crc32(loose.path))
        identities.setdefault(key, []).append(loose)
    if not identities:
        if rule.get("required", True):
            if rejected:
                raise PlanError(
                    "required payload %s was not found: %d candidate(s) matched "
                    "the source pattern but failed validation "
                    "(size/sha256/crc32/ELF), e.g. %s; the input is probably a "
                    "different build of the game"
                    % (rule["id"], rejected, rejected_example)
                )
            raise PlanError("required payload %s was not found" % rule["id"])
        return None
    if len(identities) > 1:
        raise PlanError(
            "payload %s is ambiguous (%d different matching files)"
            % (rule["id"], len(identities))
        )
    selected = next(iter(identities.values()))[0]
    if isinstance(selected, LooseFile):
        basename = selected.label
        destination = template_value(rule["destination"], abi, basename)
        validate_relative_path(destination, "destination")
        return SourceItem(rule["id"], destination, loose=selected)
    archive, info, name = selected
    basename = PurePosixPath(name).name
    destination = template_value(rule["destination"], abi, basename)
    validate_relative_path(destination, "destination")
    return SourceItem(rule["id"], destination, archive=archive, info=info)


def _choose_many(rule, group, abi):
    source = rule["source"]
    matches = []
    seen_source = set()
    for _pattern, pattern_matches in _candidate_members(group, source, abi):
        for archive, info, name in pattern_matches:
            key = (archive.path, name)
            if key in seen_source:
                continue
            seen_source.add(key)
            matches.append((archive, info, name))
    if not matches:
        if rule.get("required", True):
            raise PlanError("required payload tree %s was not found" % rule["id"])
        return []
    strip_prefix = source.get("strip_prefix", "")
    strip_prefix = template_value(strip_prefix, abi) if strip_prefix else ""
    if strip_prefix and not strip_prefix.endswith("/"):
        strip_prefix += "/"
    flatten = bool(source.get("flatten", False))
    destination_root = template_value(rule["destination"], abi)
    validate_relative_path(destination_root, "destination")
    destinations = {}
    for archive, info, name in matches:
        if strip_prefix:
            if not name.startswith(strip_prefix):
                continue
            relative = name[len(strip_prefix) :]
        else:
            relative = PurePosixPath(name).name if flatten else name
        if flatten:
            relative = PurePosixPath(relative).name
        if not relative:
            continue
        safe_zip_name(relative)
        destination = "%s/%s" % (destination_root.rstrip("/"), relative)
        validate_relative_path(destination, "destination")
        key = portable_path_key(destination)
        previous = destinations.get(key)
        if previous is not None:
            if (
                previous.destination != destination
                or previous.size != info.file_size
                or previous.crc != info.CRC
            ):
                raise PlanError(
                    "payload %s has a conflicting destination: %s"
                    % (rule["id"], destination)
                )
            continue
        destinations[key] = SourceItem(
            rule["id"], destination, archive=archive, info=info
        )
    items = sorted(
        destinations.values(),
        key=lambda item: portable_path_key(item.destination),
    )
    if not validate_summary(
        len(items), sum(item.size for item in items), source_validation(rule)
    ):
        raise PlanError("payload tree %s failed count/size validation" % rule["id"])
    return items


def _expand_commit_paths(recipe, abi):
    paths = []
    for value in recipe.data["commit"]:
        path = template_value(value, abi)
        validate_relative_path(path, "commit path")
        paths.append(path)
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            left_key = portable_path_key(left)
            right_key = portable_path_key(right)
            if (
                left_key == right_key
                or left_key.startswith(right_key + "/")
                or right_key.startswith(left_key + "/")
            ):
                raise RecipeError("expanded commit paths overlap: %s / %s" % (left, right))
    return paths


def _under_any_commit(destination, commit_paths):
    return any(
        destination == root or destination.startswith(root.rstrip("/") + "/")
        for root in commit_paths
    )


def _group_apk_member_candidates(group, member):
    """Return exact member occurrences from the APK set, never its wrapper.

    APKM/APKS/XAPK outer ZIPs and companion archives are packaging, not the
    Android payload contract.  Base and split APKs are one logical set, so a
    role may be satisfied by either without depending on their external names.
    """
    candidates = []
    for archive in group.archives:
        if archive.kind != "apk":
            continue
        info = archive.members.get(member)
        if info is not None:
            candidates.append((archive, info))
    return candidates


def _resolve_compatibility_members(recipe, group, abi):
    """Resolve required-member roles and authenticate patch profile choice."""
    compatibility = recipe.data.get("compatibility")
    if not isinstance(compatibility, dict):
        compatibility = {}
    failures = []
    declarations = normalize_required_members(
        compatibility.get("required_members"), failures.append,
        abi_order=recipe.data.get("abi_order"),
    )
    if failures:
        raise RecipeError("; ".join(failures[:3]))
    profiles = recipe.data.get("patch_profiles") or []
    profiles_by_member = {}
    for profile in profiles:
        match = profile["match_internal_payload"]
        profiles_by_member.setdefault(
            match["path"].casefold(), []
        ).append(profile)

    member_results = []
    patch_selections = []
    for declaration in declarations:
        member = declaration["member"]
        role = declaration["role"]
        variant = declaration.get("variant")
        required = (
            role == "core_required"
            or (
                role == "variant_required"
                and variant is not None
                and variant.casefold() == abi.casefold()
            )
        )
        candidates = _group_apk_member_candidates(group, member)
        present = bool(candidates)
        member_result = {
            "member": member,
            "role": role,
            "required": required,
            "present": present,
        }
        if variant is not None:
            member_result["variant"] = variant
        member_results.append(member_result)
        if required and not present:
            raise PlanError(
                "required compatibility member %s is missing for ABI %s"
                % (member, abi)
            )
        if role != "patch_selector":
            continue

        linked = profiles_by_member.get(member.casefold(), [])
        # Recipe validation requires one common fallback for every selector.
        fallback = linked[0]["fallback"]
        selection = {
            "member": member,
            "profile": None,
            "fallback": fallback,
            "state": "absent" if not present else "unknown",
        }
        if present:
            digests = set()
            for archive, info in candidates:
                try:
                    digests.add(_sha256_member(archive, info))
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise PlanError(
                        "cannot authenticate patch selector %s: %s"
                        % (member, error)
                    )
            if len(digests) != 1:
                raise PlanError(
                    "patch selector %s is ambiguous across APK splits"
                    % member
                )
            payload_sha256 = next(iter(digests))
            selection["payload_sha256"] = payload_sha256
            archive, info = candidates[0]
            matched = [
                profile for profile in linked
                if validate_member_candidate(
                    archive, info, profile["match_internal_payload"], abi
                )
            ]
            if len(matched) > 1:
                raise PlanError(
                    "patch selector %s matched multiple authenticated profiles"
                    % member
                )
            if matched:
                selection["profile"] = matched[0]["id"]
                selection["state"] = "matched"
        patch_selections.append(selection)

    result = {
        "schema": COMPATIBILITY_RESULT_SCHEMA,
        "schema_version": COMPATIBILITY_RESULT_SCHEMA_VERSION,
        "mode": "source",
        "abi": abi,
        "members": member_results,
        "patch_selections": patch_selections,
    }
    if len(canonical_json(result)) > MAX_COMPATIBILITY_RESULT_BYTES:
        raise RecipeError("compatibility result exceeds its hardening ceiling")
    return result


def _existing_compatibility_result(abi):
    """Explicit receipt for source-free adoption; no hook/profile is executed."""
    return {
        "schema": COMPATIBILITY_RESULT_SCHEMA,
        "schema_version": COMPATIBILITY_RESULT_SCHEMA_VERSION,
        "mode": "existing",
        "abi": abi,
        "members": [],
        "patch_selections": [],
    }


def build_plan_for(recipe, group, abi):
    compatibility_result = _resolve_compatibility_members(
        recipe, group, abi
    )
    commit_paths = _expand_commit_paths(recipe, abi)
    items = []
    destinations = {}
    for rule in recipe.data["extract"]:
        kind = rule["source"]["kind"]
        selected = _choose_many(rule, group, abi) if kind == "entries" else _choose_one(
            rule, group, abi
        )
        selected_items = selected if isinstance(selected, list) else ([selected] if selected else [])
        for item in selected_items:
            if not _under_any_commit(item.destination, commit_paths):
                raise RecipeError(
                    "destination %s is outside recipe commit roots" % item.destination
                )
            key = portable_path_key(item.destination)
            previous = destinations.get(key)
            if previous is not None:
                if previous.identity() != item.identity():
                    raise PlanError("two rules write conflicting path %s" % item.destination)
                continue
            destinations[key] = item
            items.append(item)
    if not items:
        raise PlanError("recipe selected no payload")
    return Plan(
        group, abi, items, commit_paths,
        compatibility_result=compatibility_result,
    )


def resolve_plan(recipe, groups, abi_override, logger, progress):
    abis = [abi_override] if abi_override else recipe.abi_order()
    successes = []
    failures = []
    progress.update(
        phase=3,
        overall=170,
        phase_progress=0,
        message="SELECTING GAME DATA BY CONTENT",
        force=True,
    )
    attempts = max(1, len(groups) * len(abis))
    attempt = 0
    for group in groups:
        for abi in abis:
            attempt += 1
            progress.update(
                phase_progress=attempt * 1000 // attempts,
                detail="%s | ABI %s" % (group.description(), abi),
            )
            try:
                plan = build_plan_for(recipe, group, abi)
            except (PlanError, ValidationError) as error:
                failure = "%s / %s: %s" % (group.description(), abi, error)
                failures.append(failure)
                logger.miss("candidate-selection", failure)
                continue
            successes.append(plan)
    if not successes:
        detail = "; ".join(failures[:8])
        raise PlanError("no input set matches this recipe%s" % (": " + detail if detail else ""))
    by_fingerprint = {}
    for plan in successes:
        by_fingerprint.setdefault(plan.fingerprint, []).append(plan)
    if len(by_fingerprint) > 1:
        descriptions = [
            "%s / ABI %s" % (plan.group.description(), plan.abi)
            for plan in successes[:8]
        ]
        raise PlanError(
            "multiple different payload sets match; keep one version or pass --input: %s"
            % "; ".join(descriptions)
        )
    equivalent = next(iter(by_fingerprint.values()))
    abi_rank = {abi: index for index, abi in enumerate(abis)}
    source_rank = {"apk-set": 0, "bundle": 1, "companion": 2}
    equivalent.sort(
        key=lambda plan: (
            abi_rank.get(plan.abi, 999),
            source_rank.get(plan.group.source_kind, 9),
            plan.group.description(),
        )
    )
    selected = equivalent[0]
    if len(equivalent) > 1:
        logger.log(
            "found %d equivalent sources; selected %s"
            % (len(equivalent), selected.group.description())
        )
    logger.log(
        "selected %s, ABI %s, %d files, %s"
        % (
            selected.group.description(),
            selected.abi,
            len(selected.items),
            human_bytes(selected.total_bytes),
        )
    )
    return selected


def _validation_paths_for_rule(recipe, rule, abi, plan=None, marker=None):
    kind = rule["source"]["kind"]
    if kind == "entries":
        return [template_value(rule["destination"], abi)]
    if plan is not None:
        return [
            item.destination for item in plan.items if item.rule_id == rule["id"]
        ]
    if marker is not None:
        return [
            item["destination"]
            for item in marker.get("items", [])
            if item.get("rule") == rule["id"]
            and isinstance(item.get("destination"), str)
        ]
    if "{basename}" in rule["destination"]:
        return []
    return [template_value(rule["destination"], abi)]


def _tree_stats(path, full):
    count = 0
    total = 0
    fingerprint = hashlib.sha256() if full else None
    required_files = []
    portable_objects = {}

    def register(relative):
        key = portable_path_key(relative)
        previous = portable_objects.get(key)
        if previous is not None and previous != relative:
            raise ValidationError(
                "tree contains a non-portable path collision: %s / %s"
                % (previous, relative)
            )
        portable_objects[key] = relative

    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        safe_directories = []
        for name in sorted(directories):
            child = os.path.join(current, name)
            if os.path.islink(child):
                raise ValidationError("tree contains symbolic link: %s" % child)
            register(os.path.relpath(child, path).replace(os.sep, "/"))
            safe_directories.append(name)
        directories[:] = safe_directories
        for name in sorted(files):
            child = os.path.join(current, name)
            if not is_private_regular_file(child):
                raise ValidationError(
                    "tree contains linked or non-regular file: %s" % child
                )
            if name.endswith((".nxpart", ".part")):
                raise ValidationError("tree contains an incomplete file: %s" % child)
            relative = os.path.relpath(child, path).replace(os.sep, "/")
            register(relative)
            size = file_size(child)
            count += 1
            total += size
            required_files.append(relative)
            if fingerprint is not None:
                encoded = relative.encode("utf-8")
                fingerprint.update(struct.pack("<I", len(encoded)))
                fingerprint.update(encoded)
                fingerprint.update(struct.pack("<QI", size, file_crc32(child)))
    return count, total, fingerprint.hexdigest() if fingerprint else None, required_files


def validate_output_path(path, spec, full=True, label=None, abi=None):
    label = label or path
    expected_type = spec.get("type")
    if os.path.islink(path):
        raise ValidationError("%s is a symbolic link" % label)
    if os.path.isdir(path):
        if expected_type not in (None, "tree", "directory"):
            raise ValidationError("%s is a directory, expected %s" % (label, expected_type))
        if not full:
            # Per-launch marker check: walking a committed tree again costs
            # minutes on SD-card handhelds. The payload was fully validated
            # before the transactional commit, so only the anchor paths are
            # re-checked here; install/update/adopt keep the full walk.
            for relative in spec.get("required_paths", []):
                candidate = os.path.join(path, *relative.split("/"))
                if not os.path.exists(candidate):
                    raise ValidationError(
                        "%s is missing required path %s" % (label, relative)
                    )
            return
        count, total, fingerprint, relative_files = _tree_stats(path, full)
        if not validate_summary(count, total, spec):
            raise ValidationError(
                "%s tree count/size mismatch (%d files, %d bytes)"
                % (label, count, total)
            )
        required = spec.get("required_paths", [])
        relative_set = set(relative_files)
        for relative in required:
            candidate = os.path.join(path, *relative.split("/"))
            if (
                relative not in relative_set
                and not os.path.isdir(candidate)
            ):
                raise ValidationError("%s is missing required path %s" % (label, relative))
        expected_fingerprint = spec.get("tree_fingerprint")
        if expected_fingerprint is not None:
            if not isinstance(expected_fingerprint, str) or not re.fullmatch(
                r"[0-9a-fA-F]{64}", expected_fingerprint
            ):
                raise RecipeError("tree_fingerprint must be SHA-256 hex")
            if full and fingerprint != expected_fingerprint.lower():
                raise ValidationError("%s tree fingerprint mismatch" % label)
        return
    if not is_private_regular_file(path):
        raise ValidationError("%s is missing, linked or not a regular file" % label)
    if expected_type in ("tree", "directory"):
        raise ValidationError("%s is a file, expected directory" % label)
    size = file_size(path)
    if not _size_valid(size, spec):
        raise ValidationError("%s has unexpected size %d" % (label, size))
    magic = parse_magic(spec)
    if magic is not None:
        with open(path, "rb") as stream:
            stream.seek(int(spec.get("magic_offset", 0)))
            actual = stream.read(len(magic))
        if actual != magic:
            raise ValidationError("%s has unexpected magic %s" % (label, actual.hex()))
    if "elf_machine" in spec:
        with open(path, "rb") as stream:
            header = stream.read(64)
        expected = _expected_elf_machine(spec, abi)
        actual = _elf_machine_from_header(header)
        if actual != expected:
            raise ValidationError(
                "%s has ELF machine %r, expected %d" % (label, actual, expected)
            )
    if full:
        crc_values = normalize_crc_list(spec.get("crc32"), "crc32")
        if crc_values:
            actual_crc = file_crc32(path)
            if actual_crc not in crc_values:
                raise ValidationError("%s CRC32 mismatch" % label)
        hashes = normalize_hash_list(spec.get("sha256"), "sha256")
        if hashes:
            actual_hash = file_sha256(path)
            if actual_hash not in hashes:
                raise ValidationError("%s SHA-256 mismatch" % label)


def validate_recipe_outputs(root, recipe, abi, plan=None, marker=None, full=True):
    checked = set()
    for rule in recipe.data["extract"]:
        paths = _validation_paths_for_rule(recipe, rule, abi, plan, marker)
        if not paths:
            if rule.get("required", True):
                raise ValidationError(
                    "cannot derive installed path for required payload %s" % rule["id"]
                )
            continue
        validation = output_validation(rule)
        for relative in paths:
            validate_relative_path(relative, "validation path")
            ensure_no_symlink_parents(root, relative)
            path = safe_join(root, relative, "validation path")
            if not os.path.exists(path) and not rule.get("required", True):
                continue
            validate_output_path(
                path,
                validation,
                full,
                "%s (%s)" % (rule["id"], relative),
                abi=abi,
            )
            checked.add(relative)
    for index, check in enumerate(recipe.data.get("validate", [])):
        relative = template_value(check["path"], abi)
        validate_relative_path(relative, "validation path")
        ensure_no_symlink_parents(root, relative)
        validate_output_path(
            safe_join(root, relative, "validation path"),
            check,
            full,
            "validation[%d] (%s)" % (index, relative),
            abi=abi,
        )
        checked.add(relative)
    commit_paths = (
        plan.commit_paths
        if plan is not None
        else marker.get("commit", [])
        if marker is not None
        else _expand_commit_paths(recipe, abi)
    )
    for relative in commit_paths:
        validate_relative_path(relative, "commit path")
        ensure_no_symlink_parents(root, relative)
        path = safe_join(root, relative, "commit path")
        if not os.path.exists(path) and not os.path.islink(path):
            raise ValidationError("commit payload is missing: %s" % relative)
    return checked


def payload_metadata_seal(root, commit_paths, mutable_paths=()):
    """Cheap per-launch seal created only after a full payload validation.
    P12: objetos listados em mutable_paths (saves que o guest grava dentro do
    payload) ficam FORA do selo — o jogo salvar nao pode invalidar o marker."""
    digest = hashlib.sha256()
    object_count = 0
    portable_objects = {}
    mutable_keys = tuple(portable_path_key(item) for item in mutable_paths)

    def is_mutable(key):
        return any(key == mk or key.startswith(mk + "/") for mk in mutable_keys)

    def add_object(kind, relative, info=None):
        nonlocal object_count
        key = portable_path_key(relative)
        if is_mutable(key):
            return
        previous = portable_objects.get(key)
        if previous is not None and previous != relative:
            raise ValidationError(
                "payload seal found a non-portable path collision: %s / %s"
                % (previous, relative)
            )
        portable_objects[key] = relative
        encoded = relative.replace(os.sep, "/").encode("utf-8")
        digest.update(kind)
        digest.update(struct.pack("<I", len(encoded)))
        digest.update(encoded)
        if info is not None:
            mtime_ns = getattr(
                info,
                "st_mtime_ns",
                int(info.st_mtime * 1_000_000_000),
            )
            digest.update(struct.pack("<QQ", info.st_size, mtime_ns))
        object_count += 1

    for commit in sorted(commit_paths, key=portable_path_key):
        ensure_no_symlink_parents(root, commit)
        path = safe_join(root, commit, "payload seal")
        try:
            mode = os.lstat(path).st_mode
        except OSError as error:
            raise ValidationError("payload seal cannot stat %s: %s" % (commit, error))
        if stat.S_ISLNK(mode):
            raise ValidationError("payload seal refuses symbolic link: %s" % commit)
        if stat.S_ISREG(mode):
            if not is_private_regular_file(path):
                raise ValidationError(
                    "payload seal refuses hard-linked file: %s" % commit
                )
            add_object(b"F", commit, os.stat(path, follow_symlinks=False))
            continue
        if not stat.S_ISDIR(mode):
            raise ValidationError("payload seal refuses special object: %s" % commit)
        add_object(b"D", commit)
        for current, directories, files in os.walk(
            path, topdown=True, followlinks=False
        ):
            directories.sort(key=portable_path_key)
            files.sort(key=portable_path_key)
            for name in directories:
                child = os.path.join(current, name)
                if os.path.islink(child):
                    raise ValidationError(
                        "payload seal refuses symbolic link: %s" % child
                    )
                relative = os.path.relpath(child, root).replace(os.sep, "/")
                add_object(b"D", relative)
            for name in files:
                child = os.path.join(current, name)
                if not is_private_regular_file(child):
                    raise ValidationError(
                        "payload seal refuses linked or non-regular file: %s" % child
                    )
                relative = os.path.relpath(child, root).replace(os.sep, "/")
                add_object(b"F", relative, os.stat(child, follow_symlinks=False))
    return digest.hexdigest(), object_count


def payload_content_seal(root, commit_paths, mutable_paths=()):
    """Stable, strong seal for recovering from filesystem metadata drift.

    FAT/exFAT/FUSE can rewrite or quantize mtimes without changing one payload
    byte. The cheap metadata seal remains the ordinary per-launch gate; this
    content seal is calculated only when publishing/migrating a marker or when
    that cheap gate changes. Paths, object kinds, sizes and bytes are covered,
    while recipe-declared mutable paths remain excluded exactly as they are
    from the metadata seal.
    """
    digest = hashlib.sha256(b"NXEXTRACT-PAYLOAD-CONTENT-v1\0")
    object_count = 0
    content_bytes = 0
    portable_objects = {}
    mutable_keys = tuple(portable_path_key(item) for item in mutable_paths)

    def is_mutable(key):
        return any(key == mk or key.startswith(mk + "/") for mk in mutable_keys)

    def add_directory(relative):
        nonlocal object_count
        key = portable_path_key(relative)
        if is_mutable(key):
            return
        previous = portable_objects.get(key)
        if previous is not None and previous != relative:
            raise ValidationError(
                "payload content seal found a non-portable path collision: %s / %s"
                % (previous, relative)
            )
        portable_objects[key] = relative
        encoded = relative.replace(os.sep, "/").encode("utf-8")
        digest.update(b"D")
        digest.update(struct.pack("<I", len(encoded)))
        digest.update(encoded)
        object_count += 1

    def add_file(relative, path):
        nonlocal object_count, content_bytes
        key = portable_path_key(relative)
        if is_mutable(key):
            return
        previous = portable_objects.get(key)
        if previous is not None and previous != relative:
            raise ValidationError(
                "payload content seal found a non-portable path collision: %s / %s"
                % (previous, relative)
            )
        portable_objects[key] = relative
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValidationError(
                "payload content seal refuses linked or non-regular file: %s"
                % relative
            )
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            identity = (before.st_dev, before.st_ino, before.st_size)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino, opened.st_size) != identity
            ):
                raise ValidationError(
                    "payload content seal file identity changed before read: %s"
                    % relative
                )
            encoded = relative.replace(os.sep, "/").encode("utf-8")
            digest.update(b"F")
            digest.update(struct.pack("<I", len(encoded)))
            digest.update(encoded)
            digest.update(struct.pack("<Q", opened.st_size))
            while True:
                block = os.read(descriptor, CHUNK_SIZE)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(descriptor)
            before_mtime = getattr(
                opened, "st_mtime_ns", int(opened.st_mtime * 1_000_000_000)
            )
            after_mtime = getattr(
                after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)
            )
            if (
                (after.st_dev, after.st_ino, after.st_size) != identity
                or after_mtime != before_mtime
            ):
                raise ValidationError(
                    "payload content changed while it was being authenticated: %s"
                    % relative
                )
        finally:
            os.close(descriptor)
        final = os.stat(path, follow_symlinks=False)
        if (final.st_dev, final.st_ino, final.st_size) != identity:
            raise ValidationError(
                "payload content seal path changed after read: %s" % relative
            )
        object_count += 1
        content_bytes += before.st_size

    for commit in sorted(commit_paths, key=portable_path_key):
        ensure_no_symlink_parents(root, commit)
        path = safe_join(root, commit, "payload content seal")
        try:
            mode = os.lstat(path).st_mode
        except OSError as error:
            raise ValidationError(
                "payload content seal cannot stat %s: %s" % (commit, error)
            )
        if stat.S_ISLNK(mode):
            raise ValidationError(
                "payload content seal refuses symbolic link: %s" % commit
            )
        if stat.S_ISREG(mode):
            add_file(commit, path)
            continue
        if not stat.S_ISDIR(mode):
            raise ValidationError(
                "payload content seal refuses special object: %s" % commit
            )
        add_directory(commit)
        for current, directories, files in os.walk(
            path, topdown=True, followlinks=False
        ):
            directories.sort(key=portable_path_key)
            files.sort(key=portable_path_key)
            for name in directories:
                child = os.path.join(current, name)
                if os.path.islink(child):
                    raise ValidationError(
                        "payload content seal refuses symbolic link: %s" % child
                    )
                relative = os.path.relpath(child, root).replace(os.sep, "/")
                add_directory(relative)
            for name in files:
                child = os.path.join(current, name)
                relative = os.path.relpath(child, root).replace(os.sep, "/")
                add_file(relative, child)
    return digest.hexdigest(), object_count, content_bytes


def marker_payload_seal_valid(marker, game_dir, mutable_paths=()):
    try:
        actual_seal, actual_count = payload_metadata_seal(
            game_dir, marker["commit"], mutable_paths
        )
    except (OSError, NXError, KeyError, TypeError):
        return False
    return (
        actual_seal == marker.get("payload_seal")
        and actual_count == marker.get("payload_objects")
    )


def _resume_item_valid(path, item, validation, abi):
    if not is_regular_file(path):
        return False
    try:
        if file_size(path) != item.size:
            return False
        if item.crc is not None:
            return file_crc32(path) == item.crc
        return validate_loose_candidate(item.loose, validation, abi) and (
            file_sha256(path) == file_sha256(item.loose.path)
        )
    except OSError:
        return False


def _copy_item(item, destination, progress, base_done, total_bytes, logger):
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    temporary = destination + ".nxpart"
    try:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        written = 0
        crc = 0
        source_context = (
            item.archive.open_member(item.info)
            if item.info is not None
            else open(item.loose.path, "rb")
        )
        with source_context as source, open(temporary, "xb") as output:
            while True:
                block = source.read(CHUNK_SIZE)
                if not block:
                    break
                output.write(block)
                written += len(block)
                crc = binascii.crc32(block, crc)
                done = base_done + written
                phase_value = done * 1000 // max(total_bytes, 1)
                progress.update(
                    phase=4,
                    overall=220 + phase_value * 430 // 1000,
                    phase_progress=phase_value,
                    done_bytes=done,
                    total_bytes=total_bytes,
                    message="EXTRACTING GAME DATA",
                    detail="%s | %s / %s"
                    % (
                        item.source_name,
                        human_bytes(done),
                        human_bytes(total_bytes),
                    ),
                )
            output.flush()
            os.fsync(output.fileno())
        if written != item.size:
            raise SourceError(
                "short extraction for %s (%d/%d bytes)"
                % (item.source_name, written, item.size)
            )
        if item.crc is not None and (crc & 0xFFFFFFFF) != item.crc:
            raise SourceError("CRC mismatch while extracting %s" % item.source_name)
        os.replace(temporary, destination)
        fsync_directory(os.path.dirname(destination))
        logger.detail(
            "extracted %s -> %s (%s)"
            % (item.source_name, item.destination, human_bytes(item.size))
        )
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def preflight_payload_space(recipe, plan, stage, logger):
    missing = 0
    rules = {rule["id"]: rule for rule in recipe.data["extract"]}
    for item in plan.items:
        destination = safe_join(stage, item.destination, "stage destination")
        ensure_no_symlink_parents(stage, item.destination)
        if not _resume_item_valid(
            destination,
            item,
            source_validation(rules[item.rule_id]),
            plan.abi,
        ):
            missing += item.size
    safety = int(recipe.data.get("space", {}).get("safety_bytes", DEFAULT_SAFETY_BYTES))
    if safety < 0:
        raise RecipeError("space.safety_bytes must not be negative")
    available = shutil.disk_usage(os.path.dirname(stage)).free
    # V3-STORAGE-01: side-by-side generations and their staging also live on
    # this card; count them so ENOSPC can never strike after the point of no
    # return and corrupt the active generation.
    runtime_overhead = 0
    runtime_root = os.path.join(
        os.path.dirname(os.path.dirname(stage)), ".nxruntime"
    )
    if os.path.isdir(runtime_root) and not os.path.islink(runtime_root):
        for overhead_dir, _dirs, overhead_files in os.walk(runtime_root):
            for overhead_name in overhead_files:
                overhead_path = os.path.join(overhead_dir, overhead_name)
                try:
                    if not os.path.islink(overhead_path):
                        runtime_overhead += os.path.getsize(overhead_path)
                except OSError:
                    continue
    required = missing + safety + runtime_overhead
    logger.log(
        "storage preflight: missing=%s safety=%s runtime=%s available=%s"
        % (human_bytes(missing), human_bytes(safety),
           human_bytes(runtime_overhead), human_bytes(available))
    )
    if available < required:
        raise SourceError(
            "not enough free space: need %s, have %s"
            % (human_bytes(required), human_bytes(available))
        )


def extract_plan(recipe, plan, stage, progress, logger):
    if os.path.lexists(stage):
        if os.path.islink(stage) or not os.path.isdir(stage):
            raise NXError("stage is linked or not a directory: %s" % stage)
    else:
        os.makedirs(stage)
    rules = {rule["id"]: rule for rule in recipe.data["extract"]}
    resumed = 0
    for item in plan.items:
        destination = safe_join(stage, item.destination, "stage destination")
        ensure_no_symlink_parents(stage, item.destination)
        validation = source_validation(rules[item.rule_id])
        if _resume_item_valid(destination, item, validation, plan.abi):
            resumed += item.size
    done = resumed
    total = plan.total_bytes
    progress.update(
        phase=4,
        overall=220 + done * 430 // max(total, 1),
        phase_progress=done * 1000 // max(total, 1),
        done_bytes=done,
        total_bytes=total,
        message="EXTRACTING GAME DATA",
        detail="resuming %s of %s" % (human_bytes(done), human_bytes(total)),
        force=True,
    )
    if resumed:
        logger.log("resuming %s of already validated staged data" % human_bytes(resumed))
    for item in plan.items:
        destination = safe_join(stage, item.destination, "stage destination")
        ensure_no_symlink_parents(stage, item.destination)
        validation = source_validation(rules[item.rule_id])
        if _resume_item_valid(destination, item, validation, plan.abi):
            continue
        _copy_item(item, destination, progress, done, total, logger)
        mode = rules[item.rule_id].get("mode")
        if mode is not None:
            try:
                numeric_mode = int(str(mode), 8)
            except ValueError:
                raise RecipeError("extract %s mode must be octal" % item.rule_id)
            if numeric_mode < 0 or numeric_mode > 0o777:
                raise RecipeError("extract %s mode is out of range" % item.rule_id)
            os.chmod(destination, numeric_mode)
        done += item.size
    progress.update(
        phase=4,
        overall=650,
        phase_progress=1000,
        done_bytes=total,
        total_bytes=total,
        message="GAME DATA EXTRACTED",
        force=True,
    )


def _format_hook_value(value, mapping):
    try:
        return value.format(**mapping)
    except (KeyError, ValueError) as error:
        raise RecipeError("invalid hook template %r: %s" % (value, error))


def _checkpoint_valid(stage, checks, abi, shadow=None):
    """Valida o checkpoint no stage; com `shadow`, cada entrada presente no
    shadow workspace e' validada la' (overlay), antes de a transacao publicar."""
    if not checks:
        return False
    try:
        for check in checks:
            relative = template_value(check["path"], abi)
            validate_relative_path(relative, "hook checkpoint")
            root = stage
            if shadow is not None and os.path.lexists(
                safe_join(shadow, relative, "hook checkpoint")
            ):
                root = shadow
            ensure_no_symlink_parents(root, relative)
            validate_output_path(
                safe_join(root, relative, "hook checkpoint"),
                check,
                full=True,
                label="hook checkpoint %s" % relative,
                abi=abi,
            )
        return True
    except (OSError, ValidationError):
        return False


HOOK_JOURNAL_FORMAT = 1


def _hook_shadow_root(hook_root, hook_id):
    return os.path.join(hook_root, hook_id + ".shadow")


def _hook_journal_path(hook_root, hook_id):
    return os.path.join(hook_root, hook_id + ".journal.json")


def _sanitize_hook_detail(line):
    """Uma linha de detalhe do hook, segura para o resumo: imprimivel, sem
    caminhos absolutos e sem nome privado de container do dono."""
    if not line:
        return ""
    text = "".join(
        character if 0x20 <= ord(character) < 0x7F else " "
        for character in line
    )
    # caminho absoluto vira so' o nome final
    text = re.sub(r"(/[^/\s:;,'\"]+)+/", "", text)
    # container do dono (apk/obb/zip e parentes) nunca aparece pelo nome
    text = re.sub(
        r"[^\s:;,'\"]*\.(apk|xapk|apks|obb|zip)\b",
        "<container>",
        text,
        flags=re.IGNORECASE,
    )
    return " ".join(text.split())[:160]


def _load_hook_journal(path, hook_id, recipe_digest, plan_fingerprint):
    journal = _load_marker(path)
    if (
        not isinstance(journal, dict)
        or journal.get("format") != HOOK_JOURNAL_FORMAT
        or journal.get("hook") != hook_id
        or journal.get("recipe_digest") != recipe_digest
        or journal.get("plan_fingerprint") != plan_fingerprint
        or journal.get("state") != "prepared"
        or not isinstance(journal.get("outputs"), list)
        or not isinstance(journal.get("fingerprint"), str)
    ):
        return None
    for output in journal["outputs"]:
        if (
            not isinstance(output, dict)
            or not isinstance(output.get("path"), str)
            or not isinstance(output.get("size"), int)
            or not isinstance(output.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", output["sha256"]) is None
        ):
            return None
        try:
            validate_relative_path(output["path"], "hook journal output")
        except ValidationError:
            return None
    return journal


def _collect_shadow_outputs(shadow, hook_id):
    """Enumera o shadow workspace do hook: caminhos relativos regulares, sem
    link, sem temporario. Cada arquivo e' sincronizado e medido aqui."""
    outputs = []
    for current, directories, files in os.walk(
        shadow, topdown=True, followlinks=False
    ):
        for name in sorted(directories):
            child = os.path.join(current, name)
            if os.path.islink(child):
                raise ValidationError(
                    "hook %s shadow contains symbolic link: %s"
                    % (hook_id, name)
                )
        for name in sorted(files):
            child = os.path.join(current, name)
            if not is_regular_file(child):
                raise ValidationError(
                    "hook %s shadow contains a non-regular file: %s"
                    % (hook_id, name)
                )
            if name.endswith((".nxpart", ".part")):
                raise ValidationError(
                    "hook %s shadow contains an incomplete file: %s"
                    % (hook_id, name)
                )
            relative = os.path.relpath(child, shadow).replace(os.sep, "/")
            validate_relative_path(relative, "hook shadow output")
            with open(child, "rb") as stream:
                os.fsync(stream.fileno())
            outputs.append(
                {
                    "path": relative,
                    "size": file_size(child),
                    "sha256": file_sha256(child),
                }
            )
    outputs.sort(key=lambda output: output["path"])
    return outputs


def _hook_outputs_fingerprint(outputs):
    return sha256_bytes(
        canonical_json(
            [
                (output["path"], output["size"], output["sha256"])
                for output in outputs
            ]
        )
    )


def _snapshot_checkpoint_inputs(stage, checks, abi):
    """Digests dos alvos de checkpoint que ja' existem no stage, ANTES do hook.
    Um hook transacional nao pode tocar os inputs validados; isto e' a prova."""
    snapshot = {}
    for check in checks or ():
        relative = template_value(check["path"], abi)
        validate_relative_path(relative, "hook checkpoint")
        path = safe_join(stage, relative, "hook checkpoint")
        if is_regular_file(path):
            snapshot[relative] = (file_size(path), file_sha256(path))
    return snapshot


def _publish_hook_outputs(stage, shadow, outputs, hook_id):
    """Move as saidas do shadow para o stage, uma renomeacao atomica por alvo.

    Roll-forward por construcao: em qualquer interrupcao cada alvo esta' ou
    inteiro no stage (ja' renomeado) ou inteiro no shadow, entao repetir a
    publicacao a partir do journal termina no mesmo resultado. A verificacao
    acontece TODA antes da primeira renomeacao: se algum alvo nao esta' em
    lugar nenhum, devolve False sem mover nada -- o stage nao ganha mistura
    nova de um journal que ja' nao fecha."""
    pending = []
    for output in outputs:
        relative = output["path"]
        source = safe_join(shadow, relative, "hook shadow output")
        ensure_no_symlink_parents(stage, relative)
        destination = safe_join(stage, relative, "hook output")
        if is_regular_file(destination) and (
            file_size(destination) == output["size"]
            and file_sha256(destination) == output["sha256"]
        ):
            continue
        if not is_regular_file(source) or (
            file_size(source) != output["size"]
            or file_sha256(source) != output["sha256"]
        ):
            return False
        pending.append((source, destination))
    directories = set()
    for source, destination in pending:
        parent = os.path.dirname(destination)
        os.makedirs(parent, exist_ok=True)
        os.replace(source, destination)
        directories.add(parent)
    for directory in sorted(directories):
        fsync_directory(directory)
    return True


def _discard_stage_for_rescan(workspace, stage, logger, reason):
    logger.log(
        "discarding staged data (%s); next run extracts from scratch" % reason
    )
    remove_path(stage)
    remove_path(os.path.join(workspace, "state.json"))
    remove_path(os.path.join(workspace, "hooks"))


def _seal_and_publish_hook_transaction(
    recipe,
    plan,
    hook,
    stage,
    workspace,
    shadow,
    journal_path,
    marker,
    checkpoint,
    inputs_snapshot,
    logger,
):
    """Fecha um hook transacional: prova os inputs, valida o conjunto inteiro
    de saidas no shadow, sela o journal e so' entao publica no stage."""
    hook_id = hook["id"]
    # 1. o hook nao pode ter alterado os inputs validados do stage
    for relative, (size, digest) in sorted(inputs_snapshot.items()):
        path = safe_join(stage, relative, "hook checkpoint")
        if (
            not is_regular_file(path)
            or file_size(path) != size
            or file_sha256(path) != digest
        ):
            remove_path(shadow)
            raise ValidationError(
                "hook %s modified validated stage input %s" % (hook_id, relative)
            )
    # 2. conjunto completo de saidas, medido e sincronizado
    try:
        outputs = _collect_shadow_outputs(shadow, hook_id)
    except ValidationError:
        remove_path(shadow)
        raise
    if not outputs:
        remove_path(shadow)
        raise ValidationError(
            "hook %s produced no outputs in its shadow workspace" % hook_id
        )
    # 3. checkpoint validado no overlay shadow+stage, ANTES de publicar
    if checkpoint and not _checkpoint_valid(
        stage, checkpoint, plan.abi, shadow=shadow
    ):
        remove_path(shadow)
        raise ValidationError(
            "hook %s checkpoint did not validate" % hook_id
        )
    # 4. SHA dos inputs substituidos entra no journal como prova
    replaced = 0
    for output in outputs:
        destination = safe_join(stage, output["path"], "hook output")
        if is_regular_file(destination):
            output["replaces"] = {
                "size": file_size(destination),
                "sha256": file_sha256(destination),
            }
            replaced += 1
    fingerprint = _hook_outputs_fingerprint(outputs)
    journal = {
        "format": HOOK_JOURNAL_FORMAT,
        "hook": hook_id,
        "recipe_digest": recipe.digest,
        "plan_fingerprint": plan.fingerprint,
        "state": "prepared",
        "counters": {
            "outputs": len(outputs),
            "replaced": replaced,
            "bytes": sum(output["size"] for output in outputs),
        },
        "outputs": outputs,
        "fingerprint": fingerprint,
    }
    atomic_write_json(journal_path, journal, required_directory_sync=True)
    logger.log(
        "hook %s sealed %d outputs (%d replacing) fingerprint %s"
        % (hook_id, len(outputs), replaced, fingerprint)
    )
    # 5. publicar: uma renomeacao atomica por alvo, roll-forward garantido
    if not _publish_hook_outputs(stage, shadow, outputs, hook_id):
        _discard_stage_for_rescan(
            workspace,
            stage,
            logger,
            "hook %s transaction is unrecoverable" % hook_id,
        )
        raise ValidationError(
            "hook %s transaction could not be published" % hook_id
        )
    if checkpoint and not _checkpoint_valid(stage, checkpoint, plan.abi):
        _discard_stage_for_rescan(
            workspace,
            stage,
            logger,
            "hook %s checkpoint failed after publication" % hook_id,
        )
        raise ValidationError(
            "hook %s checkpoint did not validate after publication" % hook_id
        )
    atomic_write_json(
        marker,
        {
            "format": FORMAT_VERSION,
            "hook": hook_id,
            "recipe_digest": recipe.digest,
            "plan_fingerprint": plan.fingerprint,
            "completed": int(time.time()),
            "transactional": True,
            "fingerprint": fingerprint,
        },
    )
    remove_path(journal_path)
    remove_path(shadow)
    fsync_directory(os.path.dirname(journal_path))


def run_hooks(recipe, plan, game_dir, stage, workspace, progress, logger):
    hooks = recipe.data.get("hooks", [])
    if not hooks:
        return
    mapping = {
        "game_dir": game_dir,
        "stage": stage,
        "workspace": workspace,
        "recipe_dir": recipe.root,
        "abi": plan.abi,
    }
    hook_root = os.path.join(workspace, "hooks")
    _ensure_real_directory(hook_root, "hook checkpoint directory")
    for index, hook in enumerate(hooks):
        checkpoint = hook.get("checkpoint", [])
        transactional = bool(hook.get("transactional"))
        marker = os.path.join(hook_root, hook["id"] + ".json")
        shadow = _hook_shadow_root(hook_root, hook["id"])
        journal_path = _hook_journal_path(hook_root, hook["id"])
        if is_regular_file(marker) and _checkpoint_valid(
            stage, checkpoint, plan.abi
        ):
            try:
                state = load_json(marker)
            except RecipeError:
                state = {}
            if (
                state.get("recipe_digest") == recipe.digest
                and state.get("plan_fingerprint") == plan.fingerprint
            ):
                if transactional:
                    # sobras de uma conclusao interrompida depois do marcador
                    remove_path(journal_path)
                    remove_path(shadow)
                logger.log("hook %s resumed from validated checkpoint" % hook["id"])
                continue
        if transactional:
            journal = _load_hook_journal(
                journal_path, hook["id"], recipe.digest, plan.fingerprint
            )
            resumed = False
            if journal is not None:
                # Publicacao interrompida: o conjunto completo ja' foi
                # validado e selado no journal, entao basta terminar de mover.
                # Se a extracao ja' restaurou alvos por cima (o resume
                # re-extrai todo item que nao casa com a origem), o shadow
                # correspondente foi consumido: descarta-se a transacao e o
                # hook reexecuta sobre inputs pristinos -- nunca sobre mistura.
                logger.log(
                    "hook %s journal found; completing interrupted publication"
                    % hook["id"]
                )
                if _publish_hook_outputs(
                    stage, shadow, journal["outputs"], hook["id"]
                ):
                    if checkpoint and not _checkpoint_valid(
                        stage, checkpoint, plan.abi
                    ):
                        _discard_stage_for_rescan(
                            workspace,
                            stage,
                            logger,
                            "hook %s checkpoint failed after recovery"
                            % hook["id"],
                        )
                        raise ValidationError(
                            "hook %s checkpoint did not validate after recovery"
                            % hook["id"]
                        )
                    atomic_write_json(
                        marker,
                        {
                            "format": FORMAT_VERSION,
                            "hook": hook["id"],
                            "recipe_digest": recipe.digest,
                            "plan_fingerprint": plan.fingerprint,
                            "completed": int(time.time()),
                            "transactional": True,
                            "fingerprint": journal["fingerprint"],
                        },
                    )
                    remove_path(journal_path)
                    remove_path(shadow)
                    fsync_directory(hook_root)
                    logger.log(
                        "hook %s resumed from output journal" % hook["id"]
                    )
                    resumed = True
                else:
                    logger.log(
                        "hook %s journal is stale; rerunning the hook over "
                        "restored inputs" % hook["id"]
                    )
            if resumed:
                continue
            # preparacao interrompida antes do selo (ou journal consumido):
            # descartar temporarios e invalidar qualquer resto; os inputs do
            # stage seguem pristinos, restaurados pela propria extracao.
            remove_path(journal_path)
            remove_path(shadow)
            _ensure_real_directory(shadow, "hook shadow workspace")
        phase_progress = index * 1000 // max(len(hooks), 1)
        progress.update(
            phase=5,
            overall=650 + index * 100 // max(len(hooks), 1),
            phase_progress=phase_progress,
            message="PROCESSING GAME DATA",
            detail=hook["id"],
            force=True,
        )
        argv = [_format_hook_value(value, mapping) for value in hook["argv"]]
        cwd_value = hook.get("cwd", "{game_dir}")
        cwd = _format_hook_value(cwd_value, mapping)
        if not os.path.isabs(cwd):
            cwd = os.path.join(game_dir, cwd)
        cwd = os.path.realpath(cwd)
        try:
            if os.path.commonpath((game_dir, cwd)) != game_dir:
                raise RecipeError("hook %s cwd escapes game directory" % hook["id"])
        except ValueError:
            raise RecipeError("hook %s cwd is invalid" % hook["id"])
        environment = os.environ.copy()
        environment.update(
            {
                "NXEXTRACT_GAME_DIR": game_dir,
                "NXEXTRACT_STAGE": stage,
                "NXEXTRACT_WORKSPACE": workspace,
                "NXEXTRACT_ABI": plan.abi,
                "NXEXTRACT_PROGRESS_FILE": progress.path or "",
                "NXEXTRACT_COMPATIBILITY_JSON": canonical_json(
                    plan.compatibility_result
                ).decode("utf-8"),
            }
        )
        if transactional:
            # Contrato transacional: as saidas nascem TODAS no shadow
            # workspace; os inputs validados do stage nao sao alterados. O
            # hook roda sem buffering para a ultima linha de detalhe ser real.
            environment["NXEXTRACT_HOOK_SHADOW"] = shadow
            environment["PYTHONUNBUFFERED"] = "1"
        extra_environment = hook.get("env", {})
        if not isinstance(extra_environment, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in extra_environment.items()
        ):
            raise RecipeError("hook %s env must be a string object" % hook["id"])
        for key, value in extra_environment.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise RecipeError("hook %s has unsafe environment name" % hook["id"])
            if key.startswith("NXEXTRACT_"):
                raise RecipeError(
                    "hook %s may not override reserved engine variable %s"
                    % (hook["id"], key)
                )
            environment[key] = _format_hook_value(value, mapping)
        inputs_snapshot = (
            _snapshot_checkpoint_inputs(stage, checkpoint, plan.abi)
            if transactional
            else None
        )
        last_detail = ""
        predicate_results = []
        hook_limits = dict(HOOK_LIMIT_DEFAULTS)
        hook_limits.update(hook.get("limits", {}))

        def _hook_resource_fence():
            # V3-HARDENING-01, closed in 1.3.0: fence the hook itself (its own
            # session/group, created by the framework), never the game process.
            #
            # A limit that cannot be established is a REFUSAL, never a silent
            # no-op. Swallowing the error left the hook running with no CPU,
            # address-space or file-size ceiling at all -- exactly the state
            # these limits exist to prevent. Raising here makes Popen fail, so
            # the hook never starts unfenced.
            import resource
            wanted = [
                ("RLIMIT_CPU", hook_limits["cpu_seconds"]),
                ("RLIMIT_AS", hook_limits["memory_bytes"]),
                ("RLIMIT_FSIZE", hook_limits["fsize_bytes"]),
            ]
            if hook_limits["nproc"] is not None:
                wanted.append(("RLIMIT_NPROC", hook_limits["nproc"]))
            if os.environ.get("NXEXTRACT_TEST_FENCE_FAULT"):
                # Test-only injection so the fail-closed path is provable.
                raise OSError(
                    "injected fence failure: %s"
                    % os.environ["NXEXTRACT_TEST_FENCE_FAULT"])
            for name, value in wanted:
                limit_id = getattr(resource, name, None)
                if limit_id is None:
                    raise OSError("%s is unavailable on this host" % name)
                soft, hard = resource.getrlimit(limit_id)
                target = value
                if hard != resource.RLIM_INFINITY:
                    target = min(target, hard)
                resource.setrlimit(limit_id, (target, target))
                confirmed, _hard = resource.getrlimit(limit_id)
                if confirmed != target:
                    raise OSError("%s did not take the requested value" % name)

        logger.log("running hook %s: %s" % (hook["id"], " ".join(argv)))
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                start_new_session=True,
                preexec_fn=_hook_resource_fence,
            )
        except (OSError, subprocess.SubprocessError) as error:
            # A fence that could not be established surfaces here, because the
            # preexec hook runs in the child before exec.
            raise NXError("cannot start hook %s: %s" % (hook["id"], error))

        def _hook_group_kill():
            # Kill ONLY the process group the framework created for this hook.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        hook_deadline = time.monotonic() + hook_limits["wall_seconds"]
        hook_output_bytes = 0
        hook_limit_violation = None

        def _process_hook_line(raw_line):
            nonlocal last_detail
            if len(raw_line) > HOOK_LINE_LIMIT:
                raw_line = raw_line[:HOOK_LINE_LIMIT]
            line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
            logger.detail("[%s] %s" % (hook["id"], line))
            if line.strip():
                last_detail = line
            match = re.match(
                r"^NXEXTRACT_PROGRESS\s+(\d+)\s+(\d+)(?:\s+(.*))?$", line
            )
            if match:
                done = int(match.group(1))
                total = max(1, int(match.group(2)))
                value = min(1000, done * 1000 // total)
                progress.update(
                    phase_progress=value,
                    detail=match.group(3) or hook["id"],
                )
            predicate = re.match(
                r"^NXEXTRACT_PREDICATE\s+"
                r"(reference_identity|compatibility|patch_selection)\s+"
                r"([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s+(ok|fail)"
                r"(?:\s+(.*))?$",
                line,
            )
            if predicate:
                predicate_results.append(
                    (
                        predicate.group(1),
                        predicate.group(2),
                        predicate.group(3),
                    )
                )

        try:
            hook_stdout = process.stdout.fileno()
            pending = b""
            while True:
                now = time.monotonic()
                if now > hook_deadline:
                    hook_limit_violation = (
                        "wall_seconds=%d" % hook_limits["wall_seconds"]
                    )
                    _hook_group_kill()
                    break
                readable, _, _ = select.select(
                    [hook_stdout], [], [], min(1.0, max(0.0, hook_deadline - now))
                )
                if not readable:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(hook_stdout, 65536)
                if not chunk:
                    break
                hook_output_bytes += len(chunk)
                if hook_output_bytes > hook_limits["output_bytes"]:
                    hook_limit_violation = (
                        "output_bytes=%d" % hook_limits["output_bytes"]
                    )
                    _hook_group_kill()
                    break
                pending += chunk
                if len(pending) > HOOK_LINE_LIMIT and b"\n" not in pending:
                    _process_hook_line(pending)
                    pending = b""
                    continue
                while b"\n" in pending:
                    raw_line, pending = pending.split(b"\n", 1)
                    _process_hook_line(raw_line)
            if pending and hook_limit_violation is None:
                _process_hook_line(pending)
            if hook_limit_violation is None:
                try:
                    status = process.wait(timeout=hook_limits["wall_seconds"])
                except subprocess.TimeoutExpired:
                    hook_limit_violation = (
                        "wall_seconds=%d" % hook_limits["wall_seconds"]
                    )
                    _hook_group_kill()
                    status = process.wait()
            else:
                status = process.wait()
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
        finally:
            if process.stdout is not None:
                process.stdout.close()
        if hook_limit_violation is not None:
            if transactional:
                remove_path(shadow)
                remove_path(journal_path)
            raise NXError(
                "hook %s exceeded its resource fence (%s) and was terminated "
                "with its process group; the validated stage was preserved"
                % (hook["id"], hook_limit_violation)
            )
        if status != 0:
            if transactional:
                # erro no meio da preparacao: descartar temporarios; os
                # inputs validados do stage nao foram tocados.
                remove_path(shadow)
                remove_path(journal_path)
            failed = [
                (klass, name)
                for klass, name, result in predicate_results
                if result == "fail"
            ]
            identity_only = failed and all(
                klass == "reference_identity" for klass, _name in failed
            )
            if identity_only:
                raise NXError(
                    "NXA0046 hook %s rejected the payload using only "
                    "reference_identity predicates (%s); identity of the "
                    "owner-provided copy must never decide compatibility"
                    % (
                        hook["id"],
                        ", ".join(name for _klass, name in failed),
                    )
                )
            predicate_note = ""
            if failed:
                predicate_note = "; failed predicates: %s" % ", ".join(
                    "%s:%s" % (klass, name) for klass, name in failed
                )
            detail = _sanitize_hook_detail(last_detail)
            raise NXError(
                "hook %s failed with status %d%s%s"
                % (
                    hook["id"],
                    status,
                    "; last detail: %s" % detail if detail else "",
                    predicate_note,
                )
            )
        if transactional:
            _seal_and_publish_hook_transaction(
                recipe,
                plan,
                hook,
                stage,
                workspace,
                shadow,
                journal_path,
                marker,
                checkpoint,
                inputs_snapshot,
                logger,
            )
        else:
            if checkpoint and not _checkpoint_valid(stage, checkpoint, plan.abi):
                raise ValidationError(
                    "hook %s checkpoint did not validate" % hook["id"]
                )
            atomic_write_json(
                marker,
                {
                    "format": FORMAT_VERSION,
                    "hook": hook["id"],
                    "recipe_digest": recipe.digest,
                    "plan_fingerprint": plan.fingerprint,
                    "completed": int(time.time()),
                },
            )
    progress.update(
        phase=5,
        overall=750,
        phase_progress=1000,
        message="GAME DATA PROCESSED",
        force=True,
    )


class WorkspaceLock:
    def __init__(self, workspace):
        self.workspace = workspace
        self.path = os.path.join(workspace, "install.lock")
        self.stream = None

    def __enter__(self):
        os.makedirs(self.workspace, exist_ok=True)
        if os.path.islink(self.workspace):
            raise NXError("workspace must not be a symbolic link")
        descriptor = _verified_regular_descriptor(
            self.path,
            os.O_RDWR | os.O_CREAT,
        )
        self.stream = os.fdopen(descriptor, "r+", encoding="utf-8")
        try:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise NXError("another extraction is already active")
            raise
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write("%d\n" % os.getpid())
        self.stream.flush()
        os.fsync(self.stream.fileno())
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.stream is not None:
            try:
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            finally:
                self.stream.close()
                self.stream = None


def _load_marker(path):
    if not is_private_regular_file(path):
        return None
    try:
        value = load_json(path)
    except RecipeError:
        return None
    return value if isinstance(value, dict) else None


def _journal_path(workspace):
    return os.path.join(workspace, "transaction.json")


def _backup_root(workspace):
    return os.path.join(workspace, "backup")


def _stage_root(workspace):
    return os.path.join(workspace, "stage")


def _ensure_real_directory(path, label):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise NXError("%s is unavailable: %s" % (label, error))
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise NXError("%s must be a real directory: %s" % (label, path))


def prepare_workspace(game_dir, identifier):
    parent = os.path.join(game_dir, ".nxextract")
    _ensure_real_directory(parent, "extractor workspace root")
    workspace = os.path.join(parent, identifier)
    _ensure_real_directory(workspace, "extractor workspace")
    return workspace


def _journal_write(workspace, journal):
    atomic_write_json(
        _journal_path(workspace),
        journal,
        required_directory_sync=True,
    )


def _transaction_id_valid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _validate_transaction_journal(recipe, journal):
    if not isinstance(journal, dict) or journal.get("format") != FORMAT_VERSION:
        raise NXError("unsafe or unsupported transaction journal")
    if not _transaction_id_valid(journal.get("transaction_id")):
        raise NXError("transaction journal has an invalid transaction ID")
    if journal.get("recipe_digest") != recipe.digest:
        raise NXError("transaction journal belongs to another recipe")
    abi = journal.get("abi")
    if not isinstance(abi, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", abi):
        raise NXError("transaction journal has an invalid ABI")
    expected_paths = _expand_commit_paths(recipe, abi)
    records = journal.get("paths")
    if not isinstance(records, list) or len(records) != len(expected_paths):
        raise NXError("transaction journal commit set does not match the recipe")
    if not isinstance(journal.get("published"), bool):
        raise NXError("transaction journal publication state is invalid")

    transaction_format = journal.get("transaction_format")
    normalized = dict(journal)
    normalized_paths = []
    if transaction_format == TRANSACTION_FORMAT_VERSION:
        if journal.get("recipe_id") != recipe.identifier:
            raise NXError("transaction journal has the wrong recipe ID")
        allowed_phases = {
            "pending",
            "backup-intent",
            "backup-skipped",
            "backed-up",
            "install-intent",
            "installed",
        }
        for expected, record in zip(expected_paths, records):
            if not isinstance(record, dict) or record.get("path") != expected:
                raise NXError("transaction journal path order does not match the recipe")
            if not isinstance(record.get("had_live"), bool):
                raise NXError("transaction journal live-data state is invalid")
            if record.get("phase") not in allowed_phases:
                raise NXError("transaction journal path phase is invalid")
            normalized_paths.append(dict(record, legacy=False))
    elif transaction_format is None:
        # Journals emitted by 1.2.0-1.2.5 before the power-loss audit used two
        # booleans. Accept only their complete, recipe-bound form and normalize
        # it in memory; arbitrary/partial legacy JSON still fails closed.
        for expected, record in zip(expected_paths, records):
            if not isinstance(record, dict) or record.get("path") != expected:
                raise NXError("legacy transaction path does not match the recipe")
            backed_up = record.get("backed_up")
            installed = record.get("installed")
            if not isinstance(backed_up, bool) or not isinstance(installed, bool):
                raise NXError("legacy transaction state is incomplete")
            phase = "installed" if installed else "backed-up" if backed_up else "pending"
            normalized_paths.append(
                {
                    "path": expected,
                    "had_live": backed_up,
                    "phase": phase,
                    "legacy": True,
                }
            )
    else:
        raise NXError("unsupported transaction journal format")
    normalized["paths"] = normalized_paths
    return normalized


def _ensure_transaction_root(workspace, name, create=False):
    path = os.path.join(workspace, name)
    if create:
        _ensure_real_directory(path, "transaction %s" % name)
    elif os.path.lexists(path):
        try:
            mode = os.lstat(path).st_mode
        except OSError as error:
            raise NXError("transaction %s is unavailable: %s" % (name, error))
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise NXError("transaction %s must be a real directory" % name)
    return path


def _safe_transaction_object(path, label):
    if not os.path.lexists(path):
        return False
    mode = os.lstat(path).st_mode
    if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise NXError("%s is linked or not a regular payload object: %s" % (label, path))
    return True


def _backup_tree_is_empty(path):
    if not os.path.lexists(path):
        return True
    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        if files:
            return False
        for name in directories:
            if os.path.islink(os.path.join(current, name)):
                return False
    return True


def _finalize_published_transaction(workspace, logger):
    cleanup_complete = True
    cleanup_paths = (
        (_backup_root(workspace), "transaction backup"),
        (_stage_root(workspace), "transaction stage"),
        (os.path.join(workspace, "source-cache"), "source cache"),
    )
    for path, label in cleanup_paths:
        if not discard_path(path, logger, label=label):
            cleanup_complete = False

    journal_path = _journal_path(workspace)
    if cleanup_complete:
        if not discard_path(journal_path, logger, label="transaction journal"):
            cleanup_complete = False
    elif os.path.lexists(journal_path):
        _best_effort_log(
            logger,
            "warning: kept transaction journal so published cleanup can retry",
        )

    fsync_directory(workspace)
    if cleanup_complete:
        _best_effort_log(
            logger, "finished cleanup of a previously published transaction"
        )
    else:
        _best_effort_log(
            logger,
            "published payload remains valid; cleanup will retry on the next run",
        )
    return cleanup_complete


def rollback_transaction(game_dir, workspace, journal, logger):
    stage = _ensure_transaction_root(workspace, "stage", create=True)
    backup = _ensure_transaction_root(workspace, "backup", create=False)
    logger.log("rolling back interrupted payload transaction")
    for item in reversed(journal.get("paths", [])):
        relative = item["path"]
        validate_relative_path(relative, "transaction path")
        destination = safe_join(game_dir, relative, "transaction destination")
        staged = safe_join(stage, relative, "transaction stage")
        previous = safe_join(backup, relative, "transaction backup")
        ensure_no_symlink_parents(game_dir, relative)
        ensure_no_symlink_parents(stage, relative)
        if os.path.lexists(backup):
            ensure_no_symlink_parents(backup, relative)
        destination_exists = _safe_transaction_object(
            destination, "transaction destination"
        )
        staged_exists = _safe_transaction_object(staged, "transaction stage")
        backup_exists = _safe_transaction_object(previous, "transaction backup")

        had_live = item["had_live"]
        if item.get("legacy"):
            # A legacy crash between rename(destination, backup) and its boolean
            # update is identified by the backup object itself. If neither
            # boolean nor backup exists and destination exists, it is the old
            # live object that was never moved.
            had_live = backup_exists or (
                item["phase"] == "pending" and destination_exists
            )

        if had_live:
            if backup_exists:
                if destination_exists:
                    if staged_exists:
                        raise NXError(
                            "ambiguous rollback state: live, stage and backup all exist "
                            "for %s" % relative
                        )
                    ensure_real_parent_directories(stage, relative)
                    durable_rename(destination, staged)
                    destination_exists = False
                    staged_exists = True
                ensure_real_parent_directories(game_dir, relative)
                durable_rename(previous, destination)
                backup_exists = False
                destination_exists = True
            elif not destination_exists:
                raise NXError(
                    "cannot restore previous live payload for %s; backup is missing"
                    % relative
                )
        else:
            if backup_exists:
                raise NXError("unexpected backup exists for new path %s" % relative)
            if destination_exists:
                if staged_exists:
                    raise NXError(
                        "ambiguous rollback state: destination and stage both exist "
                        "for %s" % relative
                    )
                ensure_real_parent_directories(stage, relative)
                durable_rename(destination, staged)

        _transaction_transition("rollback-path-%s" % relative, journal)

    fsync_directory(game_dir, required=True)
    if not _backup_tree_is_empty(backup):
        raise NXError("transaction backup contains untracked data; preserving journal")
    if os.path.lexists(backup):
        remove_path(backup)
        fsync_directory(workspace, required=True)
    try:
        os.unlink(_journal_path(workspace))
    except FileNotFoundError:
        pass
    fsync_directory(workspace, required=True)
    logger.log("payload transaction rolled back; staged work was preserved")


def recover_transaction(recipe, game_dir, workspace, marker_path, logger):
    path = _journal_path(workspace)
    if not os.path.lexists(path):
        return
    if not is_private_regular_file(path):
        raise NXError(
            "transaction journal is linked or not a private regular file: %s" % path
        )
    journal = _validate_transaction_journal(recipe, load_json(path))
    marker = _load_marker(marker_path)
    transaction_id = journal.get("transaction_id")
    if marker is not None and marker.get("transaction_id") == transaction_id:
        if marker_matches_recipe(marker, recipe):
            try:
                validate_recipe_outputs(
                    game_dir,
                    recipe,
                    marker["abi"],
                    marker=marker,
                    full=True,
                )
                _authenticate_and_reseal_marker(
                    marker_path, marker, recipe, game_dir, logger
                )
            except (OSError, NXError) as error:
                logger.log(
                    "published marker payload failed recovery validation: %s" % error
                )
            else:
                _finalize_published_transaction(workspace, logger)
                return
        else:
            logger.log("transaction marker failed schema/recipe validation")
    elif journal.get("published"):
        logger.log(
            "journal claimed publication without a matching valid marker; rolling back"
        )
    rollback_transaction(game_dir, workspace, journal, logger)


def _write_install_marker(marker_path, recipe, plan, transaction_id, game_dir):
    payload_seal, payload_objects = payload_metadata_seal(
        game_dir, plan.commit_paths, recipe.mutable_paths
    )
    payload_content, content_objects, payload_content_bytes = payload_content_seal(
        game_dir, plan.commit_paths, recipe.mutable_paths
    )
    if content_objects != payload_objects:
        raise ValidationError("payload seal object count changed during publication")
    marker = {
        "format": FORMAT_VERSION,
        "nxextract_version": NXEXTRACT_VERSION,
        "recipe_id": recipe.identifier,
        "recipe_version": recipe.version,
        "recipe_digest": recipe.digest,
        "abi": plan.abi,
        "source_kind": plan.group.source_kind,
        "package_id": plan.group.package,
        "plan_fingerprint": plan.fingerprint,
        "compatibility": plan.compatibility_result,
        "compatibility_fingerprint": sha256_bytes(
            canonical_json(plan.compatibility_result)
        ),
        "transaction_id": transaction_id,
        "completed": int(time.time()),
        "commit": list(plan.commit_paths),
        "payload_seal": payload_seal,
        "payload_objects": payload_objects,
        "payload_content_seal": payload_content,
        "payload_content_bytes": payload_content_bytes,
        "items": [
            {"rule": item.rule_id, "destination": item.destination, "size": item.size}
            for item in plan.items
        ],
    }
    atomic_write_json(
        marker_path,
        marker,
        required_directory_sync=True,
    )
    return marker


def commit_stage(recipe, plan, game_dir, workspace, marker_path, progress, logger):
    stage = _ensure_transaction_root(workspace, "stage", create=False)
    if not os.path.lexists(stage):
        raise ValidationError("transaction stage is missing")
    backup = _ensure_transaction_root(workspace, "backup", create=True)
    if not _backup_tree_is_empty(backup):
        raise NXError("transaction backup is not empty; refusing to overwrite it")
    if os.path.lexists(_journal_path(workspace)):
        raise NXError("unrecovered transaction journal blocks a new commit")
    fsync_directory(workspace, required=True)
    transaction_id = uuid.uuid4().hex
    path_records = []
    for relative in plan.commit_paths:
        destination = safe_join(game_dir, relative, "commit destination")
        staged = safe_join(stage, relative, "commit stage")
        if not _safe_transaction_object(staged, "staged commit path"):
            raise ValidationError("staged commit path is missing: %s" % relative)
        ensure_no_symlink_parents(stage, relative)
        ensure_no_symlink_parents(game_dir, relative)
        had_live = _safe_transaction_object(destination, "existing commit path")
        path_records.append(
            {
                "path": relative,
                "had_live": had_live,
                "phase": "pending",
            }
        )
    journal = {
        "format": FORMAT_VERSION,
        "transaction_format": TRANSACTION_FORMAT_VERSION,
        "transaction_id": transaction_id,
        "recipe_id": recipe.identifier,
        "recipe_digest": recipe.digest,
        "abi": plan.abi,
        "published": False,
        "paths": path_records,
    }
    _journal_write(workspace, journal)
    _transaction_transition("journal-created", journal)
    progress.update(
        phase=7,
        overall=900,
        phase_progress=0,
        message="INSTALLING VALIDATED GAME DATA",
        force=True,
    )
    try:
        for index, item in enumerate(journal["paths"]):
            relative = item["path"]
            destination = safe_join(game_dir, relative, "commit destination")
            previous = safe_join(backup, relative, "commit backup")
            staged = safe_join(stage, relative, "commit stage")
            if item["had_live"]:
                item["phase"] = "backup-intent"
                _journal_write(workspace, journal)
                _transaction_transition("backup-intent-%d" % index, journal)
                if not _safe_transaction_object(destination, "existing commit path"):
                    raise NXError("live payload disappeared before backup: %s" % relative)
                if os.path.lexists(previous):
                    raise NXError("backup destination already exists: %s" % relative)
                ensure_real_parent_directories(backup, relative)
                durable_rename(destination, previous)
                _transaction_transition("backup-renamed-%d" % index, journal)
                item["phase"] = "backed-up"
                _journal_write(workspace, journal)
                _transaction_transition("backup-recorded-%d" % index, journal)
            else:
                if os.path.lexists(destination):
                    raise NXError("new commit destination appeared unexpectedly: %s" % relative)
                item["phase"] = "backup-skipped"
                _journal_write(workspace, journal)
                _transaction_transition("backup-skipped-%d" % index, journal)

            item["phase"] = "install-intent"
            _journal_write(workspace, journal)
            _transaction_transition("install-intent-%d" % index, journal)
            if not _safe_transaction_object(staged, "staged commit path"):
                raise NXError("staged payload disappeared before install: %s" % relative)
            if os.path.lexists(destination):
                raise NXError("commit destination is occupied before install: %s" % relative)
            ensure_real_parent_directories(game_dir, relative)
            durable_rename(staged, destination)
            _transaction_transition("install-renamed-%d" % index, journal)
            item["phase"] = "installed"
            _journal_write(workspace, journal)
            _transaction_transition("install-recorded-%d" % index, journal)
            progress.update(
                phase_progress=(index + 1) * 700 // len(journal["paths"]),
                overall=900 + (index + 1) * 60 // len(journal["paths"]),
                detail=relative,
            )
        fsync_directory(game_dir, required=True)
        progress.update(
            phase=6,
            overall=970,
            phase_progress=900,
            message="VERIFYING INSTALLED GAME DATA",
            force=True,
        )
        validate_recipe_outputs(game_dir, recipe, plan.abi, plan=plan, full=True)
        _transaction_transition("payload-validated", journal)
        _write_install_marker(
            marker_path,
            recipe,
            plan,
            transaction_id,
            game_dir,
        )
        _transaction_transition("marker-published", journal)
    except Exception:
        rollback_transaction(game_dir, workspace, journal, logger)
        raise

    # The marker is the publication boundary. From here on the validated
    # payload is live, and no backup/stage/journal cleanup failure may turn the
    # install into exit 1. A stale pre-publication journal is also safe because
    # recovery recognizes the marker's transaction_id.
    journal["published"] = True
    try:
        _journal_write(workspace, journal)
        _transaction_transition("journal-published", journal)
    except OSError as error:
        _best_effort_log(
            logger,
            "warning: could not mark transaction journal published (%s)" % error,
        )
    fsync_directory(game_dir, required=True)
    _best_effort_log(logger, "validated payload committed transactionally")


class UISession:
    GRAPHICAL_READY_PROOFS = (b"visible=sdl\n", b"visible=fbdev\n")
    READY_TIMEOUT_SECONDS = 40.0

    def __init__(
        self,
        ui_option,
        require_ui,
        script_dir,
        workspace,
        progress_path,
        recipe,
        logger,
    ):
        self.ui_option = ui_option
        self.require_ui = require_ui
        self.script_dir = script_dir
        self.workspace = workspace
        self.progress_path = progress_path
        self.recipe = recipe
        self.logger = logger
        self.process = None
        self.channel = None
        self.channel_identity = None
        self.log_path = os.path.join(workspace, "ui.log")
        self.log_stream = None
        self.ready = False
        self.renderer = None
        self.headless_reason = None
        # Terminal evidence is historical, not live process state. Cleanup may
        # clear ready/renderer after the UI closes, but must never erase which
        # approved renderer was visibly attested during this run.
        self.receipt_mode = "disabled"
        self.receipt_renderer = None
        self.receipt_fallback_reason = None

    def _prepare_session_channels(self):
        self.channel, self.channel_identity = create_private_ui_session_channels()

    def _assert_session_channels(self):
        """P1 item 4: a autoridade da sessao sao os descritores ja validados.

        Nenhum pathname participa, entao a remocao do XDG_RUNTIME_DIR durante
        a extracao nao invalida uma transacao de dados ja validada. O que
        continua sendo falha fechada e' descritor trocado, fechado ou com
        propriedade divergente."""
        if self.channel is None:
            raise NXError("UI session channels are unavailable")
        for name in ("ready_read", "stop_write"):
            descriptor = self.channel.get(name)
            if descriptor is None:
                raise NXError("UI session channel %s is unavailable" % name)
            _assert_private_session_descriptor(
                descriptor, self.channel_identity[name]
            )

    def _close_channel(self, name):
        if self.channel is None:
            return
        descriptor = self.channel.pop(name, None)
        if descriptor is None:
            return
        try:
            os.close(descriptor)
        except OSError:
            pass

    def _cleanup_session_channels(self):
        """P1 item 5: limpeza idempotente e confinada a sessao.

        Fechar descritores nao toca disco algum: nao existe prova efemera no
        diretorio do jogo nem residuo em base compartilhada para remover."""
        if self.channel is None:
            return
        for name in list(self.channel):
            self._close_channel(name)
        self.channel = None
        self.channel_identity = None

    def _read_graphical_ready_proof(self, deadline):
        """Le a prova de renderer visivel pelo canal privado da sessao.

        A prova e' selada pelo fechamento do lado de escrita da UI: bytes
        exatos, terminados em newline, sem pathname para um terceiro
        substituir. EOF sem prova completa e' recusa, nao espera."""
        self._assert_session_channels()
        descriptor = self.channel["ready_read"]
        buffer = b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return buffer, False
            try:
                readable, _, _ = select.select(
                    [descriptor], [], [], min(remaining, 0.05)
                )
            except OSError as error:
                raise NXError(
                    "mandatory setup UI readiness proof is unsafe: %s" % error
                )
            if self.process is not None and self.process.poll() is not None:
                if not readable:
                    return buffer, False
            if not readable:
                continue
            chunk = os.read(descriptor, 65 - len(buffer))
            if not chunk:
                return buffer, True
            buffer += chunk
            if buffer.endswith(b"\n") or len(buffer) >= 65:
                return buffer, True

    def _validate_ready_proof(self, proof):
        if proof not in self.GRAPHICAL_READY_PROOFS:
            renderer = proof.decode("ascii", "replace").strip() or "empty"
            raise NXError(
                "mandatory setup UI did not attest an approved graphical "
                "renderer (%s)" % renderer
            )
        return proof[len(b"visible=") : -1].decode("ascii")

    def _last_ui_log_line(self):
        """Ultima linha util do log da propria UI: e o MOTIVO que o resumo
        precisa nomear (ex.: "nxextract-ui: SDL_CreateWindow failed: ...")."""
        try:
            with open(self.log_path, "rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - 4096))
                tail = stream.read(4096).decode("utf-8", "replace")
        except OSError:
            return None
        for line in reversed(tail.splitlines()):
            line = line.strip()
            if line:
                return line[:240]
        return None

    def _fallback_headless(self, reason):
        """P11.7: a UI visivel nao abriu; a instalacao NAO pode morrer por isso
        -- a UI e so a barra de progresso. Extrai headless e registra o motivo
        (ui_fallback no NXEXTRACT_RESULT). O gate de release/QA restaura o
        fail-closed com NXEXTRACT_REQUIRE_VISIBLE_UI=1."""
        detail = self._last_ui_log_line()
        message = reason if not detail else "%s; last UI line: %s" % (
            reason, detail)
        if os.environ.get("NXEXTRACT_REQUIRE_VISIBLE_UI") == "1":
            raise NXError("mandatory setup UI failed and "
                          "NXEXTRACT_REQUIRE_VISIBLE_UI=1 forbids the headless "
                          "fallback: %s" % message)
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.process.kill()
                except OSError:
                    pass
        self._cleanup_session_channels()
        self.headless_reason = message
        self.receipt_mode = "headless-fallback"
        self.receipt_renderer = None
        self.receipt_fallback_reason = message
        self.logger.log(
            "setup UI could not open a visible renderer (%s)" % message)
        self.logger.log(
            "continuing HEADLESS: installation proceeds without the visual "
            "progress bar; result will record ui_fallback=headless")
        return False

    def _find_binary(self):
        if self.ui_option in (None, "none", "off", "0"):
            return None
        if self.ui_option != "auto":
            original = os.path.abspath(self.ui_option)
            if not is_regular_file(original):
                return None
            candidate = os.path.realpath(original)
            return candidate if os.access(candidate, os.X_OK) else None
        candidates = (
            os.path.join(self.script_dir, "nxextract-ui"),
            os.path.join(self.script_dir, "ui", "build", "nxextract-ui"),
            os.path.join(self.script_dir, "build", "nxextract-ui"),
        )
        for candidate in candidates:
            if os.access(candidate, os.X_OK) and is_regular_file(candidate):
                return candidate
        return None

    def start(self):
        binary = self._find_binary()
        if not binary:
            if self.require_ui:
                return self._fallback_headless(
                    "mandatory setup UI binary is unavailable")
            return False
        try:
            self._prepare_session_channels()
        except (NXError, OSError) as error:
            if self.require_ui:
                return self._fallback_headless(
                    "setup UI session channels could not be prepared: %s"
                    % error)
            self.logger.log("setup UI unavailable (%s); continuing headless" % error)
            return False
        stop_read = self.channel["stop_read"]
        ready_write = self.channel["ready_write"]
        self.log_stream = open_private_text_append(
            self.log_path
        )
        try:
            self.process = subprocess.Popen(
                [
                    binary,
                    self.progress_path,
                    "fd:%d" % stop_read,
                    "fd:%d" % ready_write,
                    self.recipe.title,
                    self.recipe.version,
                ],
                stdin=subprocess.DEVNULL,
                stdout=self.log_stream,
                stderr=subprocess.STDOUT,
                cwd=self.workspace,
                pass_fds=(stop_read, ready_write),
            )
            self.logger.log("setup UI started with %s" % binary)
        except OSError as error:
            self.log_stream.close()
            self.log_stream = None
            self._cleanup_session_channels()
            if self.require_ui:
                return self._fallback_headless(
                    "mandatory setup UI could not start: %s" % error)
            self.logger.log("setup UI unavailable (%s); continuing headless" % error)
            return False
        finally:
            # Os lados da UI pertencem exclusivamente a ela depois do spawn:
            # o pai fecha as copias para que EOF/HUP tenham um dono so.
            self._close_channel("stop_read")
            self._close_channel("ready_write")

        if self.require_ui:
            # The approved graphical negotiation can exhaust its bounded SDL
            # retries before opening the direct-framebuffer fallback. Keep a
            # fail-closed 40-second boundary so slow ArkOS-class providers can
            # still prove the exact graphical renderer they opened.
            deadline = time.monotonic() + self.READY_TIMEOUT_SECONDS
            try:
                proof, sealed = self._read_graphical_ready_proof(deadline)
            except NXError as error:
                return self._fallback_headless(str(error))
            if not sealed or not proof:
                # EOF sem bytes vem de uma UI que fechou o canal; preservar o
                # diagnostico historico separando saida real de timeout.
                status = self.process.poll()
                if status is None and (sealed or not proof):
                    try:
                        status = self.process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        status = None
                if status is not None:
                    return self._fallback_headless(
                        "mandatory setup UI exited before opening a visible "
                        "renderer (status %s)" % status
                    )
                if sealed:
                    return self._fallback_headless(
                        "mandatory setup UI closed the readiness channel "
                        "without an approved proof")
                return self._fallback_headless(
                    "mandatory setup UI did not confirm a visible renderer "
                    "within %ds" % self.READY_TIMEOUT_SECONDS)
            try:
                renderer = self._validate_ready_proof(proof)
            except NXError as error:
                return self._fallback_headless(str(error))
            # Do not accept a proof dropped by a helper that immediately
            # died. Ongoing progress writes keep checking the child too.
            time.sleep(0.02)
            if self.process.poll() is not None:
                return self._fallback_headless(
                    "mandatory setup UI exited after publishing readiness"
                )
            self.ready = True
            self.renderer = renderer
            self.receipt_mode = "visible"
            self.receipt_renderer = renderer
            self.receipt_fallback_reason = None
            self.logger.log(
                "mandatory setup UI graphical renderer confirmed: %s"
                % renderer
            )
            return True
        return True

    def assert_visible(self):
        if self.require_ui and self.ready:
            self._assert_session_channels()
        if (
            self.require_ui
            and self.ready
            and self.process is not None
            and self.process.poll() is not None
        ):
            raise NXError("mandatory setup UI stopped before setup completed")

    def terminal_receipt(self):
        """Return the run receipt independently from cleaned-up live state."""
        return {
            "mode": self.receipt_mode,
            "renderer": self.receipt_renderer,
            "fallback_reason": self.receipt_fallback_reason,
        }

    def stop(self, delay=0):
        try:
            if self.process is not None:
                if delay > 0:
                    time.sleep(delay)
                try:
                    if self.channel is not None:
                        self._assert_session_channels()
                        os.write(self.channel["stop_write"], b"stop\n")
                except (NXError, OSError) as error:
                    _best_effort_log(
                        self.logger,
                        "warning: could not signal UI through private session "
                        "channel (%s)" % error,
                    )
                # Fechar o lado de escrita e' o reforco: mesmo que o byte se
                # perca, o HUP encerra a espera da UI.
                self._close_channel("stop_write")
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
        finally:
            if self.log_stream:
                self.log_stream.close()
            self.process = None
            self.log_stream = None
            self.ready = False
            self.renderer = None
            self._cleanup_session_channels()


def _compatibility_result_marker_valid(value, recipe, abi, source_kind):
    """Validate the bounded, source-name-free compatibility receipt in marker."""
    if not isinstance(value, dict) or set(value) != {
        "schema", "schema_version", "mode", "abi", "members",
        "patch_selections",
    }:
        return False
    try:
        if len(canonical_json(value)) > MAX_COMPATIBILITY_RESULT_BYTES:
            return False
    except (TypeError, ValueError):
        return False
    if (
        value.get("schema") != COMPATIBILITY_RESULT_SCHEMA
        or value.get("schema_version") != COMPATIBILITY_RESULT_SCHEMA_VERSION
        or value.get("abi") != abi
        or not isinstance(value.get("members"), list)
        or not isinstance(value.get("patch_selections"), list)
    ):
        return False
    if source_kind == "existing":
        return (
            value.get("mode") == "existing"
            and value["members"] == []
            and value["patch_selections"] == []
        )
    if value.get("mode") != "source":
        return False

    compatibility = recipe.data.get("compatibility")
    if not isinstance(compatibility, dict):
        compatibility = {}
    failures = []
    expected = normalize_required_members(
        compatibility.get("required_members"), failures.append,
        abi_order=recipe.data.get("abi_order"),
    )
    if failures or len(value["members"]) != len(expected):
        return False
    present_by_member = {}
    for actual, declaration in zip(value["members"], expected):
        allowed = {"member", "role", "required", "present"}
        if "variant" in declaration:
            allowed.add("variant")
        required = (
            declaration["role"] == "core_required"
            or (
                declaration["role"] == "variant_required"
                and declaration.get("variant", "").casefold() == abi.casefold()
            )
        )
        if (
            not isinstance(actual, dict)
            or set(actual) != allowed
            or actual.get("member") != declaration["member"]
            or actual.get("role") != declaration["role"]
            or actual.get("variant") != declaration.get("variant")
            or actual.get("required") is not required
            or not isinstance(actual.get("present"), bool)
            or (required and not actual["present"])
        ):
            return False
        present_by_member[declaration["member"].casefold()] = actual["present"]

    profiles_by_member = {}
    for profile in recipe.data.get("patch_profiles") or []:
        match = profile.get("match_internal_payload", {})
        path = match.get("path")
        if isinstance(path, str):
            profiles_by_member.setdefault(path.casefold(), []).append(profile)
    selectors = [
        declaration for declaration in expected
        if declaration["role"] == "patch_selector"
    ]
    if len(value["patch_selections"]) != len(selectors):
        return False
    for actual, declaration in zip(value["patch_selections"], selectors):
        if not isinstance(actual, dict):
            return False
        member = declaration["member"]
        present = present_by_member.get(member.casefold(), False)
        allowed = {"member", "profile", "fallback", "state"}
        if present:
            allowed.add("payload_sha256")
        linked = profiles_by_member.get(member.casefold(), [])
        if not linked:
            return False
        fallback = linked[0].get("fallback")
        profile_id = actual.get("profile")
        state = actual.get("state")
        if (
            set(actual) != allowed
            or actual.get("member") != member
            or actual.get("fallback") != fallback
            or state not in ("matched", "unknown", "absent")
            or (present and state == "absent")
            or (not present and state != "absent")
        ):
            return False
        if present:
            digest = actual.get("payload_sha256")
            if not isinstance(digest, str) or re.fullmatch(
                    r"[0-9a-f]{64}", digest) is None:
                return False
        if state == "matched":
            matched = [
                profile for profile in linked if profile.get("id") == profile_id
            ]
            if len(matched) != 1 or not present:
                return False
            if matched[0]["match_internal_payload"]["sha256"].casefold() != digest:
                return False
        elif profile_id is not None:
            return False
    return True


def marker_matches_recipe(marker, recipe):
    if not isinstance(marker, dict):
        return False
    abi = marker.get("abi")
    if not isinstance(abi, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", abi):
        return False
    try:
        expected_commit = _expand_commit_paths(recipe, abi)
    except RecipeError:
        return False
    marker_version = marker.get("nxextract_version")
    source_kind = marker.get("source_kind")
    package_id = marker.get("package_id")
    if (
        marker.get("format") != FORMAT_VERSION
        or marker_version not in COMPATIBLE_MARKER_VERSIONS
        or marker.get("recipe_id") != recipe.identifier
        or marker.get("recipe_version") != recipe.version
        or marker.get("recipe_digest") != recipe.digest
        or not _transaction_id_valid(marker.get("transaction_id"))
        or not isinstance(marker.get("completed"), int)
        or isinstance(marker.get("completed"), bool)
        or marker.get("completed") < 0
        or not isinstance(marker.get("plan_fingerprint"), str)
        or re.fullmatch(r"[0-9a-f]{64}", marker["plan_fingerprint"]) is None
        or not isinstance(marker.get("compatibility_fingerprint"), str)
        or re.fullmatch(
            r"[0-9a-f]{64}", marker["compatibility_fingerprint"]
        ) is None
        or not isinstance(marker.get("payload_seal"), str)
        or re.fullmatch(r"[0-9a-f]{64}", marker["payload_seal"]) is None
        or not isinstance(marker.get("payload_objects"), int)
        or isinstance(marker.get("payload_objects"), bool)
        or marker.get("payload_objects") < 1
        or marker.get("commit") != expected_commit
        or source_kind not in ("apk-set", "bundle", "companion", "existing")
        or (
            package_id is not None
            and (
                not isinstance(package_id, str)
                or not package_id
                or len(package_id) > 255
                or any(ord(character) < 32 for character in package_id)
            )
        )
    ):
        return False
    if marker_version == NXEXTRACT_VERSION and (
        not isinstance(marker.get("payload_content_seal"), str)
        or re.fullmatch(r"[0-9a-f]{64}", marker["payload_content_seal"]) is None
        or not isinstance(marker.get("payload_content_bytes"), int)
        or isinstance(marker.get("payload_content_bytes"), bool)
        or marker.get("payload_content_bytes") < 0
    ):
        return False
    compatibility = marker.get("compatibility")
    if (
        not _compatibility_result_marker_valid(
            compatibility, recipe, abi, source_kind
        )
        or marker["compatibility_fingerprint"] != sha256_bytes(
            canonical_json(compatibility)
        )
    ):
        return False
    items = marker.get("items")
    if not isinstance(items, list):
        return False
    rule_ids = {rule["id"] for rule in recipe.data["extract"]}
    seen = set()
    for item in items:
        if not isinstance(item, dict) or item.get("rule") not in rule_ids:
            return False
        destination = item.get("destination")
        size = item.get("size")
        if (
            not isinstance(destination, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            return False
        try:
            validate_relative_path(destination, "marker destination")
        except RecipeError:
            return False
        if not _under_any_commit(destination, expected_commit):
            return False
        key = (item["rule"], portable_path_key(destination))
        if key in seen:
            return False
        seen.add(key)
    return True


def _authenticate_and_reseal_marker(
    marker_path,
    marker,
    recipe,
    game_dir,
    logger,
    expected_content_seal=None,
):
    actual_metadata, actual_objects = payload_metadata_seal(
        game_dir, marker["commit"], recipe.mutable_paths
    )
    metadata_matches = (
        actual_metadata == marker.get("payload_seal")
        and actual_objects == marker.get("payload_objects")
    )
    current = marker.get("nxextract_version") == NXEXTRACT_VERSION
    if metadata_matches and current:
        return marker

    # A legacy marker has no stable content root. Re-authenticate it through
    # the recipe's full declared validation before creating one. This is the
    # same trust boundary used by the existing-data adoption path, but keeps
    # the already installed bytes in place and never starts the setup UI.
    if not current:
        if not metadata_matches and expected_content_seal is None:
            raise ValidationError(
                "legacy marker metadata drift requires an expected content seal"
            )
        validate_recipe_outputs(
            game_dir,
            recipe,
            marker["abi"],
            marker=marker,
            full=True,
        )

    content_seal, content_objects, content_bytes = payload_content_seal(
        game_dir, marker["commit"], recipe.mutable_paths
    )
    if content_objects != actual_objects:
        raise ValidationError("payload seal object count changed during validation")
    if expected_content_seal is not None and content_seal != expected_content_seal:
        raise ValidationError("payload content seal differs from expected seal")
    if current and (
        content_seal != marker.get("payload_content_seal")
        or content_bytes != marker.get("payload_content_bytes")
    ):
        raise ValidationError("payload content seal mismatch")

    migrated = dict(marker)
    previous_version = migrated.get("nxextract_version")
    migrated["nxextract_version"] = NXEXTRACT_VERSION
    migrated["payload_seal"] = actual_metadata
    migrated["payload_objects"] = actual_objects
    migrated["payload_content_seal"] = content_seal
    migrated["payload_content_bytes"] = content_bytes
    migrated["metadata_resealed"] = int(time.time())
    if previous_version != NXEXTRACT_VERSION:
        migrated["marker_migrated_from"] = previous_version
        logger.log(
            "marker migration %s -> %s: full recipe validation and content "
            "seal accepted; no extraction"
            % (previous_version, NXEXTRACT_VERSION)
        )
    else:
        logger.log(
            "payload metadata drift authenticated by stable content seal; "
            "marker resealed without extraction"
        )
    atomic_write_json(marker_path, migrated, required_directory_sync=True)
    return migrated


def marker_fast_valid(
    marker_path,
    recipe,
    game_dir,
    logger,
    expected_content_seal=None,
):
    marker = _load_marker(marker_path)
    if not marker_matches_recipe(marker, recipe):
        return None
    try:
        validate_recipe_outputs(
            game_dir,
            recipe,
            marker["abi"],
            marker=marker,
            full=False,
        )
    except (OSError, NXError) as error:
        logger.miss("marker-validation", "existing marker rejected: %s" % error)
        return None
    try:
        return _authenticate_and_reseal_marker(
            marker_path,
            marker,
            recipe,
            game_dir,
            logger,
            expected_content_seal=expected_content_seal,
        )
    except (OSError, NXError) as error:
        logger.miss(
            "marker-validation",
            "existing marker rejected: %s" % error,
        )
        return None


def try_adopt_existing(recipe, game_dir, marker_path, logger, progress, abi_override):
    abis = [abi_override] if abi_override else recipe.abi_order()
    for abi in abis:
        try:
            validate_recipe_outputs(game_dir, recipe, abi, full=True)
        except (OSError, NXError) as error:
            logger.miss(
                "existing-data",
                "existing data not adoptable for ABI %s: %s" % (abi, error)
            )
            continue
        pseudo_items = []
        for rule in recipe.data["extract"]:
            for relative in _validation_paths_for_rule(recipe, rule, abi):
                path = safe_join(game_dir, relative, "adopted payload")
                candidates = []
                if is_regular_file(path):
                    candidates.append((relative, path))
                elif os.path.isdir(path) and not os.path.islink(path):
                    for current, directories, files in os.walk(
                        path, topdown=True, followlinks=False
                    ):
                        directories.sort(key=portable_path_key)
                        files.sort(key=portable_path_key)
                        for name in files:
                            child = os.path.join(current, name)
                            child_relative = os.path.relpath(
                                child, game_dir
                            ).replace(os.sep, "/")
                            candidates.append((child_relative, child))
                for candidate_relative, candidate_path in candidates:
                    pseudo = type("AdoptedItem", (), {})()
                    pseudo.rule_id = rule["id"]
                    pseudo.destination = candidate_relative
                    pseudo.size = file_size(candidate_path)
                    pseudo.crc = None
                    pseudo_items.append(pseudo)
        pseudo_group = CandidateGroup("validated existing data", [], [], None, "existing")
        plan = Plan(
            pseudo_group,
            abi,
            pseudo_items,
            _expand_commit_paths(recipe, abi),
            compatibility_result=_existing_compatibility_result(abi),
        )
        _write_install_marker(
            marker_path,
            recipe,
            plan,
            uuid.uuid4().hex,
            game_dir,
        )
        logger.log("adopted fully validated existing data without requiring an APK")
        progress.done("EXISTING GAME DATA VALIDATED")
        return plan
    return None


def _prepare_stage_state(recipe, plan, workspace, logger):
    state_path = os.path.join(workspace, "state.json")
    stage = _stage_root(workspace)
    state = _load_marker(state_path)
    expected = {
        "format": FORMAT_VERSION,
        "recipe_digest": recipe.digest,
        "plan_fingerprint": plan.fingerprint,
        "abi": plan.abi,
    }
    if state is not None and any(state.get(key) != value for key, value in expected.items()):
        logger.log("discarding staged data made for a different recipe or payload")
        remove_path(stage)
        remove_path(os.path.join(workspace, "hooks"))
    _ensure_real_directory(stage, "transaction stage")
    atomic_write_json(state_path, expected)
    return stage


def install_command(args):
    started_monotonic = time.monotonic()
    game_dir = resolve_real_directory(args.game_dir, "game directory")
    recipe = recipe_for_game(args.recipe, game_dir)
    workspace = prepare_workspace(game_dir, recipe.identifier)
    summary_relative = recipe.data.get("log", "nxextract.log")
    log_path, summary_relative = private_game_file(
        game_dir,
        os.path.join(game_dir, summary_relative),
        "log path",
    )
    detail_path, detail_relative = private_game_file(
        game_dir,
        os.path.join(game_dir, recipe.detail_log),
        "detail log path",
    )
    result_path, _result_relative = private_game_file(
        game_dir,
        os.path.join(game_dir, recipe.terminal_result),
        "terminal result path",
    )
    progress_path = private_workspace_file(
        workspace,
        args.progress_file
        if args.progress_file
        else os.path.join(workspace, "progress.txt"),
        "progress file",
    )
    marker_path = safe_join(game_dir, recipe.marker, "marker")
    ensure_no_symlink_parents(game_dir, recipe.marker)
    ensure_real_parent_directories(game_dir, recipe.marker)
    if os.path.lexists(marker_path) and not is_private_regular_file(marker_path):
        raise NXError("installation marker must be a private regular file")
    logger = Logger(
        log_path,
        detail_path=detail_path,
        detail_label=detail_relative,
        verbose=not args.quiet,
        verbose_detail=args.verbose_log
        or os.environ.get("NXEXTRACT_VERBOSE_LOG") == "1",
    )
    progress = Progress(progress_path, logger)
    ui = UISession(
        args.ui,
        args.require_ui,
        os.path.dirname(os.path.realpath(__file__)),
        workspace,
        progress_path,
        recipe,
        logger,
    )
    archives = []
    selected_plan = None
    selected_marker = None
    validated = False

    def finish(outcome, code, error=None):
        payload = terminal_result_payload(
            recipe,
            progress,
            outcome,
            code,
            summary_relative,
            detail_relative,
            started_monotonic,
            plan=selected_plan,
            marker=selected_marker,
            validated=validated,
            error=error,
            ui=ui,
        )
        publish_terminal_result(result_path, payload)
        emit_obs_event(
            "install",
            "ok" if outcome == "success" else "failed",
            code,
            details={"recipe": recipe.identifier},
        )

    emit_obs_event("install", "begin", "NXE0000", details={"recipe": recipe.identifier})
    try:
        with WorkspaceLock(workspace):
            # Clear a prior terminal document only after owning the transaction
            # lock. A concurrent invocation must never remove the active run's
            # freshly published result while it waits for this workspace.
            try:
                os.unlink(result_path)
                fsync_directory(os.path.dirname(result_path), required=True)
            except FileNotFoundError:
                pass
            logger.log(
                "=== NXExtract %s format=%s recipe=%s version=%s ==="
                % (
                    NXEXTRACT_VERSION,
                    FORMAT_VERSION,
                    recipe.identifier,
                    recipe.version,
                )
            )
            if args.reuse_only:
                if args.force_source:
                    raise RecipeError(
                        "--reuse-only cannot be combined with --force-source"
                    )
                # This mode is a deliberately conservative binary-update
                # preflight. Recovery can rename a staged payload or roll a
                # prior transaction back, so never run it implicitly here.
                # A pending journal must be handled by a normal, explicitly
                # authorized install invocation instead.
                transaction_path = _journal_path(workspace)
                if os.path.lexists(transaction_path):
                    raise ValidationError(
                        "reuse-only refused: a pending payload transaction "
                        "requires recovery; no recovery, setup UI or extraction "
                        "was started"
                    )
            else:
                if args.expected_content_seal is not None:
                    raise RecipeError(
                        "--expected-content-seal requires --reuse-only"
                    )
                recover_transaction(
                    recipe, game_dir, workspace, marker_path, logger
                )
            if args.force_source:
                logger.log(
                    "force-source requested; bypassing the installed marker "
                    "and existing-data adoption"
                )
            else:
                selected_marker = marker_fast_valid(
                    marker_path,
                    recipe,
                    game_dir,
                    logger,
                    expected_content_seal=args.expected_content_seal,
                )
                if selected_marker is not None:
                    progress.done("GAME DATA ALREADY READY")
                    logger.log(
                        "fast validation marker accepted; no source scan needed"
                    )
                    validated = True
                    logger.terminal("TERMINAL SUCCESS NXE0001: validated marker")
                    finish("success", "NXE0001")
                    return 0
            if args.reuse_only:
                raise ValidationError(
                    "reuse-only refused: installed payload could not be "
                    "authenticated; setup UI and extraction were not started"
                )
            ui.start()
            progress.set_guard(ui.assert_visible)
            progress.update(
                phase=0,
                overall=0,
                phase_progress=0,
                message="PREPARING GAME DATA",
                force=True,
            )
            if not args.force_source:
                selected_plan = try_adopt_existing(
                    recipe,
                    game_dir,
                    marker_path,
                    logger,
                    progress,
                    args.abi,
                )
                if selected_plan is not None:
                    ui.stop(delay=float(recipe.data.get("ui_success_seconds", 1)))
                    validated = True
                    logger.terminal("TERMINAL SUCCESS NXE0002: adopted existing data")
                    finish("success", "NXE0002")
                    return 0
            progress.update(
                phase=1,
                overall=20,
                phase_progress=0,
                message="SCANNING APK AND BUNDLE CONTENTS",
                force=True,
            )
            discovery = discover_inputs(recipe, game_dir, args.input, logger)
            groups, archives = build_candidate_groups(
                recipe, discovery, workspace, logger, progress
            )
            selected_plan = resolve_plan(
                recipe, groups, args.abi, logger, progress
            )
            stage = _prepare_stage_state(
                recipe, selected_plan, workspace, logger
            )
            preflight_payload_space(recipe, selected_plan, stage, logger)
            extract_plan(recipe, selected_plan, stage, progress, logger)
            run_hooks(
                recipe,
                selected_plan,
                game_dir,
                stage,
                workspace,
                progress,
                logger,
            )
            progress.update(
                phase=6,
                overall=780,
                phase_progress=0,
                message="VALIDATING EXTRACTED GAME DATA",
                force=True,
            )
            try:
                validate_recipe_outputs(
                    stage,
                    recipe,
                    selected_plan.abi,
                    plan=selected_plan,
                    full=True,
                )
            except ValidationError:
                # O stage é reaproveitado entre execuções pelo resume, e cada
                # item é aceito sozinho. Se o CONJUNTO reprova, repetir a
                # instalação apenas revalida o mesmo stage e reprova de novo
                # para sempre — foi o que o campo mostrou ("resuming 1.2 GiB of
                # already validated staged data" seguido do mesmo erro). Um
                # payload que não passou não pode ser reaproveitado: descarta o
                # stage para que a próxima execução extraia do zero.
                logger.log(
                    "discarding staged data that failed validation "
                    "(next run extracts from scratch)"
                )
                remove_path(stage)
                remove_path(os.path.join(workspace, "state.json"))
                raise
            validated = True
            progress.update(
                phase=6,
                overall=890,
                phase_progress=1000,
                message="EXTRACTED GAME DATA VALIDATED",
                force=True,
            )
            commit_stage(
                recipe,
                selected_plan,
                game_dir,
                workspace,
                marker_path,
                progress,
                logger,
            )
            for archive in archives:
                archive.close()
            _finalize_published_transaction(workspace, logger)
            progress.done()
            _best_effort_log(logger, "=== installation complete ===")
            ui.stop(delay=float(recipe.data.get("ui_success_seconds", 1)))
            logger.terminal("TERMINAL SUCCESS NXE0000: installation complete")
            finish("success", "NXE0000")
            return 0
    except (NXError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        progress.set_guard(None)
        # Mesmo criterio de redacao do JSON terminal: a tela de setup e o log
        # que o jogador publica nao podem carregar caminho do host nem o nome
        # do arquivo do dono (a excecao crua vazava os dois).
        progress.fail(sanitize_terminal_message(error).upper())
        if ui.process is not None:
            try:
                ui.stop(delay=float(recipe.data.get("ui_error_seconds", 5)))
            except (NXError, OSError, RuntimeError) as stop_error:
                logger.detail("setup UI cleanup also failed: %s" % stop_error)
        code = stable_error_code(error)
        logger.terminal(
            "TERMINAL ERROR %s: %s" % (code, sanitize_terminal_message(error)))
        try:
            finish("error", code, error=error)
        except (NXError, OSError) as result_error:
            logger.log("ERROR: terminal result publication failed: %s" % result_error)
        return 1
    except Exception as error:
        progress.set_guard(None)
        # Mesmo criterio de redacao do JSON terminal: a tela de setup e o log
        # que o jogador publica nao podem carregar caminho do host nem o nome
        # do arquivo do dono (a excecao crua vazava os dois).
        progress.fail(sanitize_terminal_message(error).upper())
        if ui.process is not None:
            try:
                ui.stop(delay=float(recipe.data.get("ui_error_seconds", 5)))
            except Exception as stop_error:
                logger.detail("setup UI cleanup also failed: %s" % stop_error)
        code = stable_error_code(error)
        logger.terminal(
            "TERMINAL ERROR %s: %s" % (code, sanitize_terminal_message(error)))
        try:
            finish("error", code, error=error)
        except (NXError, OSError) as result_error:
            logger.log("ERROR: terminal result publication failed: %s" % result_error)
        return 1
    finally:
        for archive in archives:
            archive.close()
        ui.stop()
        logger.close()


def plan_command(args):
    game_dir = resolve_real_directory(args.game_dir, "game directory")
    recipe = recipe_for_game(args.recipe, game_dir)
    workspace = prepare_workspace(game_dir, recipe.identifier)
    logger = Logger(None, verbose=not args.quiet)
    progress = Progress(None, logger)
    archives = []
    try:
        with WorkspaceLock(workspace):
            discovery = discover_inputs(recipe, game_dir, args.input, logger)
            groups, archives = build_candidate_groups(
                recipe, discovery, workspace, logger, progress
            )
            plan = resolve_plan(recipe, groups, args.abi, logger, progress)
            output = {
                "recipe": recipe.identifier,
                "recipe_version": recipe.version,
                "group": plan.group.description(),
                "abi": plan.abi,
                "total_bytes": plan.total_bytes,
                "commit": plan.commit_paths,
                "items": [
                    {
                        "rule": item.rule_id,
                        "source_archive": item.source_label,
                        "source_entry": item.source_name,
                        "destination": item.destination,
                        "size": item.size,
                        "crc32": "%08x" % item.crc if item.crc is not None else None,
                    }
                    for item in plan.items
                ],
            }
            print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
    finally:
        for archive in archives:
            archive.close()
        logger.close()


class ScanRecipe:
    def __init__(self):
        self.data = {"extract": []}

    @property
    def input_config(self):
        return {
            "search_dirs": ["gamedata", "."],
            "prefer_first_nonempty": True,
            "sniff_all_in_primary": True,
            "extensions": list(DEFAULT_EXTENSIONS),
        }


def scan_command(args):
    game_dir = resolve_real_directory(args.game_dir, "game directory")
    logger = Logger(None, verbose=False)
    recipe = recipe_for_game(args.recipe, game_dir) if args.recipe else ScanRecipe()
    discovery = discover_inputs(recipe, game_dir, args.input, logger)
    records = []
    for kind, values in (
        ("apk", discovery.apks),
        ("bundle", discovery.bundles),
        ("archive", discovery.generic_archives),
        ("loose", discovery.loose),
    ):
        for path in values:
            record = {
                "path": path,
                "filename": os.path.basename(path),
                "kind": kind,
                "size": file_size(path),
            }
            if kind == "apk":
                archive = Archive(path, "apk")
                try:
                    record.update(
                        {
                            "package": archive.package,
                            "split": archive.split,
                            "entries": len(archive.members),
                            "abis": sorted(
                                {
                                    name.split("/")[1]
                                    for name in archive.members
                                    if name.startswith("lib/") and name.count("/") >= 2
                                }
                            ),
                        }
                    )
                finally:
                    archive.close()
            elif kind == "bundle":
                with zipfile.ZipFile(path, "r") as archive:
                    members = [
                        info
                        for info in archive.infolist()
                        if not info.is_dir()
                        and PurePosixPath(info.filename).suffix.lower() == ".apk"
                    ]
                    record["inner_apks"] = len(members)
                    record["inner_apk_bytes"] = sum(info.file_size for info in members)
            records.append(record)
    print(json.dumps({"inputs": records}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def verify_command(args):
    game_dir = resolve_real_directory(args.game_dir, "game directory")
    recipe = recipe_for_game(args.recipe, game_dir)
    marker_path = safe_join(game_dir, recipe.marker, "marker")
    marker = _load_marker(marker_path)
    if not marker_matches_recipe(marker, recipe):
        raise ValidationError("matching installation marker was not found")
    validate_recipe_outputs(
        game_dir, recipe, marker["abi"], marker=marker, full=True
    )
    logger = Logger(None, verbose=False)
    try:
        marker = _authenticate_and_reseal_marker(
            marker_path,
            marker,
            recipe,
            game_dir,
            logger,
            expected_content_seal=args.expected_content_seal,
        )
    finally:
        logger.close()
    print(
        "OK: %s version %s, ABI %s"
        % (recipe.title, recipe.version, marker["abi"])
    )
    return 0


def content_seal_command(args):
    """Print a read-only stable seal for an already installed payload."""
    game_dir = resolve_real_directory(args.game_dir, "game directory")
    recipe = recipe_for_game(args.recipe, game_dir)
    marker_path = safe_join(game_dir, recipe.marker, "marker")
    marker = _load_marker(marker_path)
    if not marker_matches_recipe(marker, recipe):
        raise ValidationError("matching installation marker was not found")
    validate_recipe_outputs(
        game_dir, recipe, marker["abi"], marker=marker, full=True
    )
    seal, objects, content_bytes = payload_content_seal(
        game_dir, marker["commit"], recipe.mutable_paths
    )
    print(
        json.dumps(
            {
                "content_bytes": content_bytes,
                "objects": objects,
                "payload_content_seal": seal,
            },
            sort_keys=True,
        )
    )
    return 0


def recipe_check_command(args):
    recipe = Recipe(args.recipe)
    print(
        "OK: recipe=%s version=%s digest=%s"
        % (recipe.identifier, recipe.version, recipe.digest)
    )
    return 0


def progress_command(args):
    progress = Progress(args.file)
    progress.update(
        phase=args.phase,
        overall=args.overall,
        phase_progress=args.phase_progress,
        done_bytes=args.done_bytes,
        total_bytes=args.total_bytes,
        message=args.message,
        detail=args.detail,
        state=args.state,
        force=True,
    )
    return 0


def expected_content_seal_argument(value):
    normalized = value.lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        raise argparse.ArgumentTypeError(
            "expected content seal must be exactly 64 hexadecimal characters"
        )
    return normalized


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nxextract",
        description="Content-driven universal APK/APKM/APKS/XAPK extractor",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="NXExtract %s" % NXEXTRACT_VERSION,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(subparser, recipe_required=True):
        subparser.add_argument(
            "--recipe", required=recipe_required, help="per-port JSON extraction recipe"
        )
        subparser.add_argument("--game-dir", required=True, help="port data directory")
        subparser.add_argument(
            "--input",
            action="append",
            default=[],
            help="explicit input path; repeat for a loose split set",
        )
        subparser.add_argument("--abi", help="override the recipe ABI selection")
        subparser.add_argument("--quiet", action="store_true")

    install = subparsers.add_parser("install", help="extract, validate and commit data")
    add_common(install)
    install.add_argument(
        "--ui",
        default="auto",
        help="auto, none, or a path to nxextract-ui (default: auto)",
    )
    install.add_argument(
        "--require-ui",
        action="store_true",
        help="fail before extraction unless the setup UI confirms a visible renderer",
    )
    install.add_argument("--progress-file", help="override progress protocol path")
    install.add_argument(
        "--verbose-log",
        action="store_true",
        help=(
            "copy per-file and hook-output detail into the compact log "
            "(also enabled by NXEXTRACT_VERBOSE_LOG=1)"
        ),
    )
    install.add_argument(
        "--force-source",
        action="store_true",
        help=(
            "scan and transactionally reinstall from source even when the "
            "current payload is valid"
        ),
    )
    install.add_argument(
        "--reuse-only",
        action="store_true",
        help=(
            "authenticate/migrate already installed data or fail before the "
            "setup UI, source scan and extraction"
        ),
    )
    install.add_argument(
        "--expected-content-seal",
        type=expected_content_seal_argument,
        help=(
            "expected stable payload seal for a metadata-drifted legacy "
            "marker; valid only with --reuse-only"
        ),
    )
    install.set_defaults(handler=install_command)

    plan = subparsers.add_parser("plan", help="resolve sources without extracting payload")
    add_common(plan)
    plan.set_defaults(handler=plan_command)

    scan = subparsers.add_parser("scan", help="classify candidate files by contents")
    scan.add_argument("--game-dir", required=True)
    scan.add_argument("--recipe")
    scan.add_argument("--input", action="append", default=[])
    scan.set_defaults(handler=scan_command)

    verify = subparsers.add_parser("verify", help="fully verify an installed payload")
    verify.add_argument("--recipe", required=True)
    verify.add_argument("--game-dir", required=True)
    verify.add_argument(
        "--expected-content-seal", type=expected_content_seal_argument
    )
    verify.set_defaults(handler=verify_command)

    content_seal = subparsers.add_parser(
        "content-seal", help="read and print the stable seal of installed data"
    )
    content_seal.add_argument("--recipe", required=True)
    content_seal.add_argument("--game-dir", required=True)
    content_seal.set_defaults(handler=content_seal_command)

    recipe_check = subparsers.add_parser("recipe-check", help="validate a recipe")
    recipe_check.add_argument("--recipe", required=True)
    recipe_check.set_defaults(handler=recipe_check_command)

    progress = subparsers.add_parser(
        "progress", help="write one NXEXTRACT_V1 progress update for a hook"
    )
    progress.add_argument("--file", required=True)
    progress.add_argument("--state", type=int, default=1)
    progress.add_argument("--phase", type=int, default=5)
    progress.add_argument("--overall", type=int, default=650)
    progress.add_argument("--phase-progress", type=int, default=0)
    progress.add_argument("--done-bytes", type=int, default=0)
    progress.add_argument("--total-bytes", type=int, default=0)
    progress.add_argument("--message", default="PROCESSING GAME DATA")
    progress.add_argument("--detail", default="")
    progress.set_defaults(handler=progress_command)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args) or 0)
    except (NXError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        print("nxextract: ERROR: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
