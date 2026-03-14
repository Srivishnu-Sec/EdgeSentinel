package edgesentinel.devices

import future.keywords.if
import future.keywords.in

# Allowed actions per role
allowed_actions := {
    "temperature_sensor": {"publish_temperature", "publish_humidity", "ping"},
    "gateway": {"publish_temperature", "publish_humidity", "ping", "shutdown", "update_firmware", "delete_peer"},
    "monitor": {"ping", "read_logs"}
}

# Device roles
device_roles := {
    "pizero": "temperature_sensor",
    "esp32_1": "temperature_sensor",
    "esp32_rogue": "unknown"
}

# Default deny
default allow := false

# Allow if registered, known role, and action permitted
allow if {
    role := device_roles[input.device_id]
    role != "unknown"
    input.action in allowed_actions[role]
}

# Violation cases
default violation := false

violation if {
    not input.device_id in object.keys(device_roles)
}

violation if {
    device_roles[input.device_id] == "unknown"
}

violation if {
    role := device_roles[input.device_id]
    role != "unknown"
    not input.action in allowed_actions[role]
}

# Violation reason
violation_reason := "Device not registered in policy engine" if {
    not input.device_id in object.keys(device_roles)
}

violation_reason := "Device has unknown role — not trusted" if {
    input.device_id in object.keys(device_roles)
    device_roles[input.device_id] == "unknown"
}

violation_reason := reason if {
    role := device_roles[input.device_id]
    role != "unknown"
    not input.action in allowed_actions[role]
    reason := concat("", ["Action '", input.action, "' not permitted for role '", role, "'"])
}
