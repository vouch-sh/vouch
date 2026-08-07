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
  // No SOURCE_DATE_EPOCH here: it is a predefined BuildKit arg that stamps
  // the epoch into WORKDIR/COPY op digests, forking the layer-cache chain.
  // The Dockerfile's ARG default (0) still governs the builder-stage touch.
  args = {
    TARGET         = TARGET
    CARGO_PROFILE  = "ci"
    CARGO_PACKAGES = "-p vouch-cli -p vouch-agent -p vouch-server"
    GENERATE_SBOM  = "false"
  }
}

target "cli" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
}

target "server" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-server"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
}

target "reproduce" {
  inherits = ["_common"]
  args = {
    TARGET            = TARGET
    CARGO_PACKAGES    = "-p vouch-cli -p vouch-agent"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = "false"
  }
}
