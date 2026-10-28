"""Engine API: the Python core exposed to a UI over JSON-RPC.

Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (see
:mod:`xray_forge.engine.server`).  No network port is opened, so nothing else
on the machine can talk to the engine.  Long-running work runs as *jobs* that
stream ``job.event`` notifications.
"""

PROTOCOL_VERSION = 1
