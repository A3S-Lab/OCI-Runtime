use a3s_oci_sdk::{Error, ErrorCode, Result, Signal};

pub(super) fn parse(value: &str) -> Result<Signal> {
    if let Ok(number) = value.parse::<i32>() {
        return Signal::new(number);
    }

    let upper = value.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let number = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" | "CLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" | "UNUSED" => 31,
        "RTMIN" => 34,
        "RTMAX" => 64,
        _ => parse_realtime(name).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("unsupported Linux signal {value:?}"),
            )
            .for_operation("kill")
        })?,
    };
    Signal::new(number)
}

fn parse_realtime(value: &str) -> Option<i32> {
    if let Some(offset) = value.strip_prefix("RTMIN+") {
        let offset = offset.parse::<i32>().ok()?;
        return (0..=30).contains(&offset).then_some(34 + offset);
    }
    if let Some(offset) = value.strip_prefix("RTMAX-") {
        let offset = offset.parse::<i32>().ok()?;
        return (0..=30).contains(&offset).then_some(64 - offset);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse;
    use a3s_oci_sdk::ErrorCode;

    #[test]
    fn accepts_required_names_aliases_and_numbers() {
        assert_eq!(parse("TERM").expect("TERM").get(), 15);
        assert_eq!(parse("sigkill").expect("SIGKILL").get(), 9);
        assert_eq!(parse("USR1").expect("USR1").get(), 10);
        assert_eq!(parse("29").expect("numeric signal").get(), 29);
        assert_eq!(parse("RTMIN+4").expect("realtime signal").get(), 38);
        assert_eq!(parse("SIGRTMAX-2").expect("realtime signal").get(), 62);
    }

    #[test]
    fn rejects_zero_unknown_and_out_of_range_realtime_names() {
        for value in ["0", "BOGUS", "RTMIN+31", "RTMAX-31"] {
            let error = parse(value).expect_err("signal must be rejected");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
    }
}
