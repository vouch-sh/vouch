variable "TARGET" {
  default = ""
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

variable "GENERATE_SBOM" {
  default = "false"
}

variable "WRITE_CACHE" {
  // "true" only on main-branch CI runs. GHA cache entries written from PR,
  // merge-queue, or tag refs are readable only by that same ref, so writing
  // from them burns the repo's 10 GB Actions cache budget (evicting the
  // shared main-scoped entries every ref restores from) without ever
  // producing a cache hit. Reads (cache-from) stay enabled everywhere:
  // any ref may restore caches written from the default branch.
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

target "ci" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent -p vouch-server"
    SOURCE_DATE_EPOCH = "0"
    GENERATE_SBOM     = "false"
  }
  cache-from = ["type=gha,scope=bake-ci-${TARGET}"]
  cache-to   = WRITE_CACHE == "true" ? ["type=gha,mode=max,ignore-error=true,scope=bake-ci-${TARGET}"] : []
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
