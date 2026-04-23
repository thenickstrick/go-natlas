-- name: AgentConfigGet :one
SELECT * FROM agent_config WHERE id = 1;

-- name: AgentConfigUpdate :one
UPDATE agent_config SET
    version_detection        = ?,
    os_detection             = ?,
    enable_scripts           = ?,
    only_opens               = ?,
    scan_timeout_s           = ?,
    web_screenshots          = ?,
    vnc_screenshots          = ?,
    web_screenshot_timeout_s = ?,
    vnc_screenshot_timeout_s = ?,
    script_timeout_s         = ?,
    host_timeout_s           = ?,
    os_scan_limit            = ?,
    no_ping                  = ?,
    udp_scan                 = ?,
    scripts                  = ?
WHERE id = 1
RETURNING *;

-- name: NatlasServicesGet :one
SELECT * FROM natlas_services WHERE id = 1;

-- name: NatlasServicesUpdate :exec
UPDATE natlas_services
SET sha256 = ?, services = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = 1;
