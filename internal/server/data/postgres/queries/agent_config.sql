-- name: AgentConfigGet :one
SELECT * FROM agent_config WHERE id = 1;

-- name: AgentConfigUpdate :one
UPDATE agent_config SET
    version_detection        = $1,
    os_detection             = $2,
    enable_scripts           = $3,
    only_opens               = $4,
    scan_timeout_s           = $5,
    web_screenshots          = $6,
    vnc_screenshots          = $7,
    web_screenshot_timeout_s = $8,
    vnc_screenshot_timeout_s = $9,
    script_timeout_s         = $10,
    host_timeout_s           = $11,
    os_scan_limit            = $12,
    no_ping                  = $13,
    udp_scan                 = $14,
    scripts                  = $15
WHERE id = 1
RETURNING *;

-- name: NatlasServicesGet :one
SELECT * FROM natlas_services WHERE id = 1;

-- name: NatlasServicesUpdate :exec
UPDATE natlas_services
SET sha256 = $1, services = $2, updated_at = NOW()
WHERE id = 1;
