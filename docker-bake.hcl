variable "TARGET" {
  default = ""
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

variable "GENERATE_SBOM" {
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
    DEPS_STAGE        = "full-deps"
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent -p vouch-server"
    SOURCE_DATE_EPOCH = "0"
    GENERATE_SBOM     = "false"
  }
  cache-from = ["type=gha,scope=bake-ci-${TARGET}"]
  cache-to   = ["type=gha,mode=max,ignore-error=true,scope=bake-ci-${TARGET}"]
}

target "cli" {
  inherits = ["_common"]
  args = {
    DEPS_STAGE        = "cli-deps"
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
  cache-from = ["type=gha,scope=bake-cli-${TARGET}"]
  cache-to   = ["type=gha,mode=max,ignore-error=true,scope=bake-cli-${TARGET}"]
}

target "server" {
  inherits = ["_common"]
  args = {
    DEPS_STAGE        = "full-deps"
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-server"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
  cache-from = ["type=gha,scope=bake-server-${TARGET}"]
  cache-to   = ["type=gha,mode=max,ignore-error=true,scope=bake-server-${TARGET}"]
}

target "reproduce" {
  inherits = ["_common"]
  args = {
    DEPS_STAGE        = "cli-deps"
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = "false"
  }
  // Read from the cli cache but never write, to avoid polluting it.
  cache-from = ["type=gha,scope=bake-cli-${TARGET}"]
  cache-to   = []
}
