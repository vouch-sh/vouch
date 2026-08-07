variable "TARGET" {
  default = ""
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

variable "GENERATE_SBOM" {
  default = "false"
}

variable "CACHE_IMAGE" {
  // Registry ref for the shared dependency layer cache, e.g.
  // ghcr.io/vouch-sh/vouch/buildcache. Registry storage keeps the multi-GB
  // Rust layer cache out of the repo's 10 GB GitHub Actions cache budget.
  // Empty (local builds) disables the remote cache; the local BuildKit
  // layer cache still applies.
  default = ""
}

variable "WRITE_CACHE" {
  // "true" only on main-branch CI runs. The deps cache is shared by every
  // ref, so only post-merge builds may publish it: PR and merge-queue runs
  // read the cache but never write, keeping unmerged dependency trees out
  // of the shared cache. For the remaining GHA-backed scopes (cli/server),
  // ref-scoped writes would also burn the 10 GB Actions cache budget
  // without ever producing a cache hit.
  default = "false"
}

group "default" {
  targets = ["ci"]
}

target "_common" {
  dockerfile = "Dockerfile.build"
  context    = "."
  output     = ["type=local,dest=."]
}

// Dependency layers only (through `cargo chef cook`). Built alongside `ci`
// in CI so the reusable layers can be published to the registry cache
// without also exporting the per-commit source and workspace-compile
// layers, which change on every push and can never produce a cache hit.
target "deps" {
  inherits = ["_common"]
  target   = "deps"
  output   = ["type=cacheonly"]
  args = {
    TARGET        = TARGET
    CARGO_PROFILE = "ci"
  }
  cache-from = CACHE_IMAGE != "" ? ["type=registry,ref=${CACHE_IMAGE}:deps-ci-${TARGET}"] : []
  cache-to   = CACHE_IMAGE != "" && WRITE_CACHE == "true" ? ["type=registry,ref=${CACHE_IMAGE}:deps-ci-${TARGET},mode=max,image-manifest=true,oci-mediatypes=true,ignore-error=true"] : []
}

target "ci" {
  inherits = ["_common"]
  // No SOURCE_DATE_EPOCH here: it is a predefined BuildKit arg that stamps
  // the epoch into WORKDIR/COPY op digests, forking this target's cache
  // chain away from `deps` — the only chain published to CACHE_IMAGE. The
  // Dockerfile's ARG default (0) still governs the builder-stage touch.
  args = {
    TARGET         = TARGET
    CARGO_PROFILE  = "ci"
    CARGO_PACKAGES = "-p vouch-cli -p vouch-agent -p vouch-server"
    GENERATE_SBOM  = "false"
  }
  cache-from = CACHE_IMAGE != "" ? ["type=registry,ref=${CACHE_IMAGE}:deps-ci-${TARGET}"] : []
  cache-to   = []
}

target "cli" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
  cache-from = ["type=gha,scope=bake-cli-${TARGET}"]
  cache-to   = WRITE_CACHE == "true" ? ["type=gha,mode=max,ignore-error=true,scope=bake-cli-${TARGET}"] : []
}

target "server" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-server"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
  cache-from = ["type=gha,scope=bake-server-${TARGET}"]
  cache-to   = WRITE_CACHE == "true" ? ["type=gha,mode=max,ignore-error=true,scope=bake-server-${TARGET}"] : []
}

target "reproduce" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = "false"
  }
  // Read from the cli cache but never write, to avoid polluting it.
  cache-from = ["type=gha,scope=bake-cli-${TARGET}"]
  cache-to   = []
}
