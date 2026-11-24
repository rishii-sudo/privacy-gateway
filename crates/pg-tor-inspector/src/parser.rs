use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAX_INPUT_SIZE: usize = 65536; // 64 KB

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapData {
    pub progress: u8,
    pub tag: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    pub ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayData {
    pub fingerprint: String,
    pub nickname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitData {
    pub id: String,
    pub status: String,
    pub path: Vec<RelayData>,
    pub build_flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitEstablishedData {
    pub established: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventData {
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub details: HashMap<String, String>,
}

pub fn parse_bootstrap(payload: &str) -> Result<BootstrapData, String> {
    if payload.trim().is_empty() {
        return Err("empty bootstrap payload".to_string());
    }

    // Strip leading 250 status line prefix if present
    let line = payload
        .lines()
        .find(|l| l.contains("BOOTSTRAP"))
        .unwrap_or(payload);

    let mut progress: Option<u8> = None;
    let mut tag: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut warning: Option<String> = None;

    // Tokenize key=value or "key=value with spaces"
    let tokens = tokenize_protocol_line(line);
    for (k, v) in tokens {
        match k.to_uppercase().as_str() {
            "PROGRESS" => {
                if let Ok(p) = v.parse::<u8>() {
                    if p <= 100 {
                        progress = Some(p);
                    }
                }
            }
            "TAG" => tag = Some(v),
            "SUMMARY" => summary = Some(v),
            "WARNING" => warning = Some(v),
            _ => {}
        }
    }

    let p =
        progress.ok_or_else(|| "missing or invalid PROGRESS in bootstrap payload".to_string())?;
    let t = tag.unwrap_or_else(|| "unknown".to_string());
    let s = summary.unwrap_or_else(|| "Unknown bootstrap status".to_string());
    let ready = p == 100 && (t == "done" || t.is_empty());

    Ok(BootstrapData {
        progress: p,
        tag: t,
        summary: s,
        warning,
        ready,
    })
}

pub fn parse_circuits(payload: &str) -> Result<Vec<CircuitData>, String> {
    let mut circuits = Vec::new();

    for line in payload.lines() {
        let trimmed = line.trim();
        // Skip control lines like "250 OK"
        if trimmed.is_empty() || trimmed == "250 OK" || trimmed.starts_with("250+") {
            continue;
        }

        // Strip prefix like "250-circuit-status=" or "250 "
        let content = if let Some(idx) = trimmed.find("circuit-status=") {
            &trimmed[idx + "circuit-status=".len()..]
        } else if let Some(stripped) = trimmed.strip_prefix("250-") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("250 ") {
            stripped
        } else {
            trimmed
        };

        if content.is_empty() || content == "." {
            continue;
        }

        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let id = parts[0].to_string();
        let status = parts[1].to_uppercase();

        // Validate allowed circuit status
        let valid_statuses = ["LAUNCHED", "BUILT", "EXTENDED", "FAILED", "CLOSED"];
        if !valid_statuses.contains(&status.as_str()) {
            return Err(format!("unknown circuit status: {}", status));
        }

        let mut path = Vec::new();
        let mut build_flags = Vec::new();
        let mut purpose = None;
        let mut time_created = None;

        for part in &parts[2..] {
            if part.contains('=') {
                let kv: Vec<&str> = part.splitn(2, '=').collect();
                match kv[0].to_uppercase().as_str() {
                    "PURPOSE" => purpose = Some(kv[1].to_string()),
                    "TIME_CREATED" => time_created = Some(kv[1].to_string()),
                    "BUILD_FLAGS" => {
                        build_flags = kv[1].split(',').map(|s| s.to_string()).collect();
                    }
                    _ => {}
                }
            } else if part.contains('$') || part.contains('~') || part.contains(',') {
                // Relay path: e.g. $FINGERPRINT~Nickname,$FINGERPRINT~Nickname
                for relay_str in part.split(',') {
                    let cleaned = relay_str.trim();
                    if cleaned.is_empty() {
                        continue;
                    }
                    let relay_parts: Vec<&str> = cleaned.splitn(2, '~').collect();
                    let fp = relay_parts[0].trim_start_matches('$').to_string();
                    let nick = if relay_parts.len() > 1 {
                        relay_parts[1].to_string()
                    } else {
                        "Unnamed".to_string()
                    };
                    path.push(RelayData {
                        fingerprint: fp,
                        nickname: nick,
                    });
                }
            }
        }

        circuits.push(CircuitData {
            id,
            status,
            path,
            build_flags,
            purpose,
            time_created,
        });
    }

    Ok(circuits)
}

pub fn parse_circuit_established(payload: &str) -> Result<CircuitEstablishedData, String> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Err("empty payload".to_string());
    }

    let val_str = if let Some(idx) = trimmed.find("circuit-established=") {
        &trimmed[idx + "circuit-established=".len()..]
    } else {
        trimmed
    };

    let first_token = val_str.split_whitespace().next().unwrap_or("0");
    match first_token {
        "1" => Ok(CircuitEstablishedData { established: true }),
        "0" => Ok(CircuitEstablishedData { established: false }),
        _ => Err(format!(
            "invalid circuit-established value: {}",
            first_token
        )),
    }
}

pub fn parse_event(payload: &str) -> Result<EventData, String> {
    let trimmed = payload.trim();
    // 650 EVENT_NAME [SEVERITY] [ACTION] [ARGS...]
    let stripped = trimmed.strip_prefix("650").unwrap_or(trimmed).trim();
    let parts: Vec<&str> = stripped.split_whitespace().collect();
    if parts.is_empty() {
        return Err("empty event payload".to_string());
    }

    let event_type = parts[0].to_uppercase();
    let mut severity = None;
    let mut action = None;
    let mut detail_start = 1;

    if parts.len() > 1 {
        let second = parts[1].to_uppercase();
        if ["DEBUG", "INFO", "NOTICE", "WARN", "ERR"].contains(&second.as_str()) {
            severity = Some(second);
            detail_start = 2;
        }
    }

    if parts.len() > detail_start {
        let third = parts[detail_start].to_uppercase();
        if ["BOOTSTRAP", "CIRC", "STREAM", "ORCONN"].contains(&third.as_str()) {
            action = Some(third);
            detail_start += 1;
        }
    }

    let remaining = parts[detail_start..].join(" ");
    let details = tokenize_protocol_line(&remaining)
        .into_iter()
        .collect::<HashMap<String, String>>();

    Ok(EventData {
        event_type,
        severity,
        action,
        details,
    })
}

// Tokenizes lines honoring quoted strings: KEY="VALUE WITH SPACES"
fn tokenize_protocol_line(line: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut chars = line.chars().peekable();

    while chars.peek().is_some() {
        // Skip whitespace
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }

        // Read key
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            key.push(c);
            chars.next();
        }

        if chars.peek() == Some(&'=') {
            chars.next(); // Consume '='
            let mut val = String::new();
            if chars.peek() == Some(&'"') {
                chars.next(); // Consume opening quote
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    val.push(c);
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    val.push(c);
                    chars.next();
                }
            }
            if !key.is_empty() {
                pairs.push((key, val));
            }
        } else if !key.is_empty() {
            // Standalone token (key without value)
            pairs.push((key, String::new()));
        }
    }

    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootstrap_success() {
        let raw =
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"";
        let res = parse_bootstrap(raw).unwrap();
        assert_eq!(res.progress, 100);
        assert_eq!(res.tag, "done");
        assert_eq!(res.summary, "Done");
        assert!(res.ready);
    }

    #[test]
    fn test_parse_bootstrap_in_progress_with_warning() {
        let raw = "BOOTSTRAP PROGRESS=45 TAG=onehop_create SUMMARY=\"Establishing an encrypted directory connection\" WARNING=\"slow network\"";
        let res = parse_bootstrap(raw).unwrap();
        assert_eq!(res.progress, 45);
        assert_eq!(res.tag, "onehop_create");
        assert_eq!(res.warning, Some("slow network".to_string()));
        assert!(!res.ready);
    }

    #[test]
    fn test_parse_bootstrap_invalid() {
        assert!(parse_bootstrap("").is_err());
        assert!(parse_bootstrap("NO PROGRESS HERE").is_err());
    }

    #[test]
    fn test_parse_circuits_success() {
        let raw = "250+circuit-status=\n1 BUILT $1111111111111111111111111111111111111111~Guard,$2222222222222222222222222222222222222222~Middle PURPOSE=GENERAL\n2 LAUNCHED PURPOSE=GENERAL\n.\n250 OK";
        let circuits = parse_circuits(raw).unwrap();
        assert_eq!(circuits.len(), 2);
        assert_eq!(circuits[0].id, "1");
        assert_eq!(circuits[0].status, "BUILT");
        assert_eq!(circuits[0].path.len(), 2);
        assert_eq!(circuits[0].path[0].nickname, "Guard");
        assert_eq!(circuits[1].id, "2");
        assert_eq!(circuits[1].status, "LAUNCHED");
        assert!(circuits[1].path.is_empty());
    }

    #[test]
    fn test_parse_circuit_established() {
        assert!(
            parse_circuit_established("250-status/circuit-established=1\n250 OK")
                .unwrap()
                .established
        );
        assert!(!parse_circuit_established("0").unwrap().established);
        assert!(parse_circuit_established("invalid").is_err());
    }

    #[test]
    fn test_parse_event() {
        let raw =
            "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=80 TAG=conn_dir SUMMARY=\"Connecting\"";
        let evt = parse_event(raw).unwrap();
        assert_eq!(evt.event_type, "STATUS_CLIENT");
        assert_eq!(evt.severity, Some("NOTICE".to_string()));
        assert_eq!(evt.action, Some("BOOTSTRAP".to_string()));
        assert_eq!(evt.details.get("PROGRESS"), Some(&"80".to_string()));
    }
}
