# Vouch agent — en-US message catalog.
#
# Operator messages emitted by the agent daemon binary when invoked
# directly. Internal `tracing` logs stay English regardless of locale —
# they target operators/developers, not end users.

agent-running = Agent is running
agent-not-running = Agent is not running
agent-status-err = Error checking status: { $reason }
agent-already-running = Agent is already running. Use --stop to stop it.
agent-check-running-err = Error checking if agent is running: { $reason }
agent-daemonize-err = Failed to daemonize: { $reason }
agent-pid-file-err = Error getting PID file path: { $reason }
agent-not-running-no-pid = Agent is not running (no PID file)
agent-pid-read-err = Failed to read PID file: { $reason }
agent-pid-invalid = Invalid PID in file
agent-stop-signal-sent = Sent stop signal to agent (PID { $pid })
agent-stopped = Agent stopped
agent-shutting-down = Agent is shutting down...
agent-stop-signal-failed = Failed to send signal to agent (PID { $pid })
agent-stop-unsupported = Stop command not supported on this platform
