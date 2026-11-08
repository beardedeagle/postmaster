//! Dotenv syntax from dotenvy 0.15.7 with bounded expansion and redacted errors.
//! MIT notice: `licenses/dotenvy-MIT.txt`.

use std::io::{BufRead, BufReader};
use std::path::Path;

use std::collections::HashMap;
use std::env;

use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const INVALID: &str = "invalid dotenv syntax";
const LIMIT: &str = "dotenv resource limit exceeded";
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PARSED_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536;

type ParsedLine = Result<Option<(String, Zeroizing<String>)>>;

fn parse_line(
    line: &str,
    substitution_data: &mut HashMap<String, Option<Zeroizing<String>>>,
    budget: &mut Budget,
) -> ParsedLine {
    let mut parser = LineParser::new(line, substitution_data, budget);
    parser.parse_line()
}

struct LineParser<'parse> {
    substitution_data: &'parse mut HashMap<String, Option<Zeroizing<String>>>,
    line: &'parse str,
    budget: &'parse mut Budget,
}

impl<'parse> LineParser<'parse> {
    fn new(
        line: &'parse str,
        substitution_data: &'parse mut HashMap<String, Option<Zeroizing<String>>>,
        budget: &'parse mut Budget,
    ) -> LineParser<'parse> {
        LineParser {
            substitution_data,
            line: line.trim_end(),
            budget,
        }
    }

    fn parse_line(&mut self) -> ParsedLine {
        self.skip_whitespace();
        // if its an empty line or a comment, skip it
        if self.line.is_empty() || self.line.starts_with('#') {
            return Ok(None);
        }

        self.budget.entry()?;
        let mut key = self.parse_key()?;
        self.skip_whitespace();

        // export can be either an optional prefix or a key itself
        if key == "export" {
            // here we check for an optional `=`, below we throw directly when it’s not found.
            if self.expect_equal().is_err() {
                key = self.parse_key()?;
                self.skip_whitespace();
                self.expect_equal()?;
            }
        } else {
            self.expect_equal()?;
        }
        self.skip_whitespace();

        if self.line.is_empty() || self.line.starts_with('#') {
            self.budget.retain(key.len())?;
            self.substitution_data.insert(key.clone(), None);
            return Ok(Some((key, Zeroizing::new(String::new()))));
        }

        let parsed_value = parse_value(self.line, self.substitution_data)?;
        self.budget.retain(key.len() + parsed_value.len())?;
        self.substitution_data
            .insert(key.clone(), Some(parsed_value.clone()));

        Ok(Some((key, parsed_value)))
    }

    fn parse_key(&mut self) -> Result<String> {
        if !self
            .line
            .starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        {
            return Err(INVALID);
        }
        let index = match self
            .line
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        {
            Some(index) => index,
            None => self.line.len(),
        };
        let key = String::from(&self.line[..index]);
        self.line = &self.line[index..];
        Ok(key)
    }

    fn expect_equal(&mut self) -> Result<()> {
        if !self.line.starts_with('=') {
            return Err(INVALID);
        }
        self.line = &self.line[1..];
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        if let Some(index) = self.line.find(|c: char| !c.is_whitespace()) {
            self.line = &self.line[index..];
        } else {
            self.line = "";
        }
    }
}

#[derive(Eq, PartialEq)]
enum SubstitutionMode {
    None,
    Block,
    EscapedBlock,
}

fn parse_value(
    input: &str,
    substitution_data: &mut HashMap<String, Option<Zeroizing<String>>>,
) -> Result<Zeroizing<String>> {
    let mut strong_quote = false; // '
    let mut weak_quote = false; // "
    let mut escaped = false;
    let mut expecting_end = false;

    let mut output = Zeroizing::new(String::new());

    let mut substitution_mode = SubstitutionMode::None;
    let mut substitution_name = String::new();

    for c in input.chars() {
        // A whitespace-separated comment ends the value; an attached # stays literal.
        if expecting_end {
            if c == ' ' || c == '\t' {
                continue;
            } else if c == '#' {
                break;
            } else {
                return Err(INVALID);
            }
        } else if escaped {
            match c {
                '\\' | '\'' | '"' | '$' | ' ' => push_char(&mut output, c)?,
                'n' => push_char(&mut output, '\n')?, // handle \n case
                _ => {
                    return Err(INVALID);
                }
            }

            escaped = false;
        } else if strong_quote {
            if c == '\'' {
                strong_quote = false;
            } else {
                push_char(&mut output, c)?;
            }
        } else if substitution_mode != SubstitutionMode::None {
            if c.is_alphanumeric() {
                substitution_name.push(c);
            } else {
                match substitution_mode {
                    SubstitutionMode::None => unreachable!(),
                    SubstitutionMode::Block => {
                        if c == '{' && substitution_name.is_empty() {
                            substitution_mode = SubstitutionMode::EscapedBlock;
                        } else {
                            apply_substitution(substitution_data, &substitution_name, &mut output)?;
                            substitution_name.clear();
                            if c == '$' {
                                substitution_mode = if !strong_quote && !escaped {
                                    SubstitutionMode::Block
                                } else {
                                    SubstitutionMode::None
                                }
                            } else {
                                substitution_mode = SubstitutionMode::None;
                                push_char(&mut output, c)?;
                            }
                        }
                    }
                    SubstitutionMode::EscapedBlock => {
                        if c == '}' {
                            substitution_mode = SubstitutionMode::None;
                            apply_substitution(substitution_data, &substitution_name, &mut output)?;
                            substitution_name.clear();
                        } else {
                            substitution_name.push(c);
                        }
                    }
                }
            }
        } else if c == '$' {
            substitution_mode = if !strong_quote && !escaped {
                SubstitutionMode::Block
            } else {
                SubstitutionMode::None
            }
        } else if weak_quote {
            if c == '"' {
                weak_quote = false;
            } else if c == '\\' {
                escaped = true;
            } else {
                push_char(&mut output, c)?;
            }
        } else if c == '\'' {
            strong_quote = true;
        } else if c == '"' {
            weak_quote = true;
        } else if c == '\\' {
            escaped = true;
        } else if c == ' ' || c == '\t' {
            expecting_end = true;
        } else {
            push_char(&mut output, c)?;
        }
    }

    if substitution_mode == SubstitutionMode::EscapedBlock || strong_quote || weak_quote {
        Err(INVALID)
    } else {
        apply_substitution(substitution_data, &substitution_name, &mut output)?;
        Ok(output)
    }
}

fn apply_substitution(
    substitution_data: &HashMap<String, Option<Zeroizing<String>>>,
    substitution_name: &str,
    output: &mut String,
) -> Result<()> {
    if let Ok(value) = env::var(substitution_name) {
        let value = Zeroizing::new(value);
        push_str(output, &value)?;
    } else if let Some(Some(value)) = substitution_data.get(substitution_name) {
        push_str(output, value)?;
    }
    Ok(())
}

fn push_str(output: &mut String, value: &str) -> Result<()> {
    if value.len() > MAX_VALUE_BYTES.saturating_sub(output.len()) {
        return Err(LIMIT);
    }
    output.push_str(value);
    Ok(())
}

fn push_char(output: &mut String, value: char) -> Result<()> {
    let mut bytes = [0; 4];
    push_str(output, value.encode_utf8(&mut bytes))
}
struct QuotedLines<B> {
    buf: B,
}

enum ParseState {
    Complete,
    Escape,
    StrongOpen,
    StrongOpenEscape,
    WeakOpen,
    WeakOpenEscape,
    Comment,
    WhiteSpace,
}

fn eval_end_state(prev_state: ParseState, buf: &str) -> (usize, ParseState) {
    let mut cur_state = prev_state;
    let mut cur_pos: usize = 0;

    for (pos, c) in buf.char_indices() {
        cur_pos = pos;
        cur_state = match cur_state {
            ParseState::WhiteSpace => match c {
                '#' => return (cur_pos, ParseState::Comment),
                '\\' => ParseState::Escape,
                '"' => ParseState::WeakOpen,
                '\'' => ParseState::StrongOpen,
                _ => ParseState::Complete,
            },
            ParseState::Escape => ParseState::Complete,
            ParseState::Complete => match c {
                c if c.is_whitespace() && c != '\n' && c != '\r' => ParseState::WhiteSpace,
                '\\' => ParseState::Escape,
                '"' => ParseState::WeakOpen,
                '\'' => ParseState::StrongOpen,
                _ => ParseState::Complete,
            },
            ParseState::WeakOpen => match c {
                '\\' => ParseState::WeakOpenEscape,
                '"' => ParseState::Complete,
                _ => ParseState::WeakOpen,
            },
            ParseState::WeakOpenEscape => ParseState::WeakOpen,
            ParseState::StrongOpen => match c {
                '\\' => ParseState::StrongOpenEscape,
                '\'' => ParseState::Complete,
                _ => ParseState::StrongOpen,
            },
            ParseState::StrongOpenEscape => ParseState::StrongOpen,
            // Comments last the entire line.
            ParseState::Comment => return (cur_pos, ParseState::Comment),
        };
    }
    (cur_pos, cur_state)
}

impl<B: BufRead> Iterator for QuotedLines<B> {
    type Item = Result<Zeroizing<String>>;

    fn next(&mut self) -> Option<Result<Zeroizing<String>>> {
        let mut buf = Zeroizing::new(String::new());
        let mut cur_state = ParseState::Complete;
        let mut buf_pos;
        let mut cur_pos;
        loop {
            buf_pos = buf.len();
            match self.buf.read_line(&mut buf) {
                Ok(0) => match cur_state {
                    ParseState::Complete => return None,
                    _ => {
                        return Some(Err(INVALID));
                    }
                },
                Ok(_n) => {
                    // Skip lines which start with a # before iteration
                    // This optimizes parsing a bit.
                    if buf.trim_start().starts_with('#') {
                        return Some(Ok(Zeroizing::new(String::new())));
                    }
                    let result = eval_end_state(cur_state, &buf[buf_pos..]);
                    cur_pos = result.0;
                    cur_state = result.1;

                    match cur_state {
                        ParseState::Complete => {
                            if buf.ends_with('\n') {
                                buf.pop();
                                if buf.ends_with('\r') {
                                    buf.pop();
                                }
                            }
                            return Some(Ok(buf));
                        }
                        ParseState::Escape
                        | ParseState::StrongOpen
                        | ParseState::StrongOpenEscape
                        | ParseState::WeakOpen
                        | ParseState::WeakOpenEscape
                        | ParseState::WhiteSpace => {}
                        ParseState::Comment => {
                            buf.truncate(buf_pos + cur_pos);
                            return Some(Ok(buf));
                        }
                    }
                }
                Err(_) => return Some(Err(INVALID)),
            }
        }
    }
}

/// Cumulative work across every dotenv file, including shadowed and metadata entries.
#[derive(Default)]
pub(super) struct Budget {
    entries: usize,
    bytes: usize,
    input_bytes: usize,
}

impl Budget {
    fn entry(&mut self) -> Result<()> {
        if self.entries == MAX_ENTRIES {
            return Err(LIMIT);
        }
        self.entries += 1;
        Ok(())
    }

    fn retain(&mut self, bytes: usize) -> Result<()> {
        if bytes > MAX_PARSED_BYTES.saturating_sub(self.bytes) {
            return Err(LIMIT);
        }
        self.bytes += bytes;
        Ok(())
    }
}

/// Read a regular, non-symlink file with a byte cap, then parse with bounded substitutions.
pub(super) fn read(
    path: &Path,
    budget: &mut Budget,
    authorized: Option<&[[u8; 32]]>,
) -> std::result::Result<Vec<(String, Zeroizing<String>)>, String> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: {e} (refusing to follow a symlink)", path.display()))?;
    let stat = fstat(&fd).map_err(|e| format!("{}: stat: {e}", path.display()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(format!("{}: not a regular file", path.display()));
    }
    let raw = Zeroizing::new(crate::server::read_capped(std::fs::File::from(fd), path)?);
    if raw.len() > MAX_PARSED_BYTES.saturating_sub(budget.input_bytes) {
        return Err(format!("{}: {LIMIT}", path.display()));
    }
    budget.input_bytes += raw.len();
    if let Some(authorized) = authorized {
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(&raw).into();
        if !authorized.contains(&hash) {
            return Err(format!(
                "{}: dotenv source is not authorized",
                path.display()
            ));
        }
    }
    parse(&raw, budget).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse(raw: &[u8], budget: &mut Budget) -> Result<Vec<(String, Zeroizing<String>)>> {
    let lines = QuotedLines {
        buf: BufReader::new(raw),
    };
    let mut substitutions = HashMap::new();
    let mut values = Vec::new();
    for line in lines {
        if let Some(pair) = parse_line(&line?, &mut substitutions, budget)? {
            values.push(pair);
        }
    }
    Ok(values)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn matches_dotenv_grammar_and_substitution() {
        let _guard = crate::test_util::ENV_LOCK.lock().unwrap();
        let corpus = [
            "",
            "# comment\n",
            "A=\n",
            "export A=one\n",
            "export=one\n",
            "A=one#two\n",
            "A=one # two\n",
            "A='one\ntwo'\n",
            "A=\"one\\ntwo\"\n",
            "A=one\\ two\n",
            "A='x'\"y\"z\n",
            "A=x\nB=${A}${A}\n",
            "A=x\nA=y\nB=$A\n",
            "A=x\nB=$A-$A\n",
            "A=x\nB=\"${A}z\"\n",
            "A=x\nB='${A}'\n",
            "A=x\nB=\\$A\n",
            "A=x\nB=${MISSING}\n",
            "A=\nB=${A}\n",
            "A=x\nB=$A$A\n",
            "A=x\nB=${A}\nC=${B}\n",
            "A=\"unterminated",
            "A=one two\n",
            "A='unterminated",
            "A=\"bad\\q\"\n",
            "A=${oops\n",
            "1A=x\n",
            "A.B=x\n",
            "A=x\r\nB=y\r\n",
            "\u{feff}A=x\n",
            "A=x\\\n",
            "A=\"x\n# inside\ny\"\n",
            "A=\"x\" trailing\n",
            "A=\"λ\"\n",
            "A=${PATH}\n",
            "A='x\\'\n",
            "A=x  \nB=y\n",
        ];
        for input in corpus {
            let expected = dotenvy::from_read_iter(input.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>();
            let actual = parse(input.as_bytes(), &mut Budget::default());
            match (expected, actual) {
                (Ok(expected), Ok(actual)) => assert_eq!(
                    expected,
                    actual
                        .into_iter()
                        .map(|(k, v)| (k, (*v).clone()))
                        .collect::<Vec<_>>(),
                    "{input:?}"
                ),
                (Err(_), Err(INVALID)) => {}
                _ => panic!("parser outcome differs for {input:?}"),
            }
        }
    }

    #[test]
    fn bounds_expansion_and_counts_shadowed_metadata() {
        let mut input = "A0=x\n".to_string();
        for i in 1..40 {
            input.push_str(&format!("A{i}=${{A{}}}${{A{}}}\n", i - 1, i - 1));
        }
        assert!(input.len() < 2048);
        assert_eq!(
            parse(input.as_bytes(), &mut Budget::default()).unwrap_err(),
            LIMIT
        );
        let input = "DOTENV_METADATA=\n".repeat(MAX_ENTRIES + 1);
        assert_eq!(
            parse(input.as_bytes(), &mut Budget::default()).unwrap_err(),
            LIMIT
        );
        let mut budget = Budget {
            bytes: MAX_PARSED_BYTES,
            ..Budget::default()
        };
        assert_eq!(parse(b"A=x\n", &mut budget).unwrap_err(), LIMIT);
    }

    #[test]
    fn rejects_special_and_oversized_sources() {
        let dir = crate::test_util::temp_dir::TestDir::new("dotenv-source");
        let fifo = dir.join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            read(&fifo, &mut Budget::default(), None)
                .unwrap_err()
                .contains("not a regular file")
        );
        let path = dir.join("large");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(16 * 1024 * 1024 + 1)
            .unwrap();
        assert!(
            read(&path, &mut Budget::default(), None)
                .unwrap_err()
                .contains("size cap")
        );
    }
}
