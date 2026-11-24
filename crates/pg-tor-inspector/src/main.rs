#![forbid(unsafe_code)]

mod parser;

use parser::{
    parse_bootstrap, parse_circuit_established, parse_circuits, parse_event, MAX_INPUT_SIZE,
};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
struct Request {
    version: String,
    command: String,
    payload: String,
}

#[derive(Debug, Serialize)]
struct Response<T: Serialize> {
    version: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

fn error_response<T: Serialize>(code: &str, message: &str) -> Response<T> {
    Response {
        version: "1.0".to_string(),
        status: "error".to_string(),
        data: None,
        error_code: Some(code.to_string()),
        message: Some(message.to_string()),
    }
}

fn ok_response<T: Serialize>(data: T) -> Response<T> {
    Response {
        version: "1.0".to_string(),
        status: "ok".to_string(),
        data: Some(data),
        error_code: None,
        message: None,
    }
}

pub fn read_bounded_line<R: BufRead>(reader: &mut R, max_len: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut total_read = 0;
    let mut line_truncated = false;

    loop {
        let (done, used) = match reader.fill_buf() {
            Ok(n) if n.is_empty() => {
                if buf.is_empty() && !line_truncated {
                    return Ok(None);
                }
                (true, 0)
            }
            Ok(n) => {
                if let Some(pos) = n.iter().position(|&b| b == b'\n') {
                    let take_bytes = pos + 1;
                    if !line_truncated {
                        if total_read + pos <= max_len {
                            buf.extend_from_slice(&n[..pos]);
                        } else {
                            line_truncated = true;
                        }
                    }
                    (true, take_bytes)
                } else {
                    let take_bytes = n.len();
                    if !line_truncated {
                        if total_read + take_bytes <= max_len {
                            buf.extend_from_slice(n);
                            total_read += take_bytes;
                        } else {
                            line_truncated = true;
                        }
                    }
                    (false, take_bytes)
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        reader.consume(used);
        if done {
            break;
        }
    }

    if line_truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ERR_OVERSIZED_INPUT: request line exceeds maximum 64KB bounded limit",
        ));
    }

    if buf.last() == Some(&b'\r') {
        buf.pop();
    }

    let s = String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Some(s))
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut reader = stdin.lock();

    loop {
        let line = match read_bounded_line(&mut reader, MAX_INPUT_SIZE) {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                let err_str = e.to_string();
                let code = if err_str.contains("ERR_OVERSIZED_INPUT") {
                    "ERR_OVERSIZED_INPUT"
                } else {
                    "ERR_MALFORMED_INPUT"
                };
                let resp: Response<()> = error_response(code, &err_str);
                if let Ok(json_out) = serde_json::to_string(&resp) {
                    let _ = writeln!(stdout, "{}", json_out);
                    let _ = stdout.flush();
                }
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp: Response<()> = error_response(
                    "ERR_MALFORMED_INPUT",
                    &format!("failed to parse JSON request: {}", e),
                );
                if let Ok(json_out) = serde_json::to_string(&resp) {
                    let _ = writeln!(stdout, "{}", json_out);
                    let _ = stdout.flush();
                }
                continue;
            }
        };

        if req.version != "1.0" {
            let resp: Response<()> = error_response(
                "ERR_UNSUPPORTED_VERSION",
                &format!("unsupported protocol version: {}", req.version),
            );
            if let Ok(json_out) = serde_json::to_string(&resp) {
                let _ = writeln!(stdout, "{}", json_out);
                let _ = stdout.flush();
            }
            continue;
        }

        let output_res = match req.command.as_str() {
            "parse_bootstrap" => match parse_bootstrap(&req.payload) {
                Ok(data) => serde_json::to_string(&ok_response(data)),
                Err(err) => {
                    serde_json::to_string(&error_response::<()>("ERR_PARSE_BOOTSTRAP", &err))
                }
            },
            "parse_circuits" => match parse_circuits(&req.payload) {
                Ok(data) => serde_json::to_string(&ok_response(data)),
                Err(err) => {
                    serde_json::to_string(&error_response::<()>("ERR_PARSE_CIRCUITS", &err))
                }
            },
            "parse_circuit_established" => match parse_circuit_established(&req.payload) {
                Ok(data) => serde_json::to_string(&ok_response(data)),
                Err(err) => serde_json::to_string(&error_response::<()>(
                    "ERR_PARSE_CIRCUIT_ESTABLISHED",
                    &err,
                )),
            },
            "parse_event" => match parse_event(&req.payload) {
                Ok(data) => serde_json::to_string(&ok_response(data)),
                Err(err) => serde_json::to_string(&error_response::<()>("ERR_PARSE_EVENT", &err)),
            },
            other => serde_json::to_string(&error_response::<()>(
                "ERR_UNKNOWN_COMMAND",
                &format!("unknown command: {}", other),
            )),
        };

        if let Ok(json_str) = output_res {
            let _ = writeln!(stdout, "{}", json_str);
            let _ = stdout.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_bounded_line_normal() {
        let data = b"line one\r\nline two\nline three";
        let mut cursor = Cursor::new(data);

        let l1 = read_bounded_line(&mut cursor, 64).unwrap();
        assert_eq!(l1, Some("line one".to_string()));

        let l2 = read_bounded_line(&mut cursor, 64).unwrap();
        assert_eq!(l2, Some("line two".to_string()));

        let l3 = read_bounded_line(&mut cursor, 64).unwrap();
        assert_eq!(l3, Some("line three".to_string()));

        let l4 = read_bounded_line(&mut cursor, 64).unwrap();
        assert_eq!(l4, None);
    }

    #[test]
    fn test_read_bounded_line_oversized() {
        // Line exceeding limit followed by a valid line
        let mut data = vec![b'x'; 100];
        data.push(b'\n');
        data.extend_from_slice(b"valid line\n");

        let mut cursor = Cursor::new(data);

        // Limit is 50, so the 100-byte line must fail with ERR_OVERSIZED_INPUT
        let err = read_bounded_line(&mut cursor, 50).unwrap_err();
        assert!(err.to_string().contains("ERR_OVERSIZED_INPUT"));

        // Subsequent line should be read cleanly without stream corruption
        let next = read_bounded_line(&mut cursor, 50).unwrap();
        assert_eq!(next, Some("valid line".to_string()));
    }
}
