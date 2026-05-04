//! Procedural macros for ocfg - OpenWrt Configuration Tool
//!
//! This crate provides compile-time identifier generation, case transformation,
//! and debugging macros tailored for the ocfg project.
//!
//! # Macros
//!
//! ## Paste Macros
//! - [`paste_ident!`] - Concatenate segments into an identifier with optional case transforms
//! - [`paste_str!`] - Concatenate segments into a string literal
//! - [`paste!`] - Full paste macro with bracket syntax [<...>]
//!
//! ## Debug Macros
//! - [`dbg_loc!`] - Captures file, line, column as a struct
//! - [`dbg_ctx!`] - Full debug context with timestamp, module, and location
//! - [`dbg_here!`] - Quick debug print with location info
//! - [`dbg_scope!`] - Creates a named debug scope with entry/exit tracking
//! - [`dbg_fn`] - Attribute macro for function entry/exit logging
//! - [`dbg_time!`] - Log with high-resolution timestamp
//! - [`compile_info!`] - Returns compile date/time and version info
//! - [`loc_str!`] - Current location as string
//! - [`mod_str!`] - Current module path
//! - [`fn_name!`] - Captures enclosing function name
//!
//! ## OpenWrt-Specific Macros
//! - [`uciname!`] - Generate UCI config option names
//! - [`ucipath!`] - Generate UCI config path identifiers
//!
//! # Example
//!
//! ```ignore
//! use ocfg_macros::{paste_ident, dbg_here, dbg_ctx, uciname};
//!
//! // Creates identifier: get_wifi_config
//! paste_ident!(get_ [snake]"WifiConfig");
//!
//! // Debug with location info
//! dbg_here!("checkpoint reached");
//! let ctx = dbg_ctx!();
//!
//! // Generate UCI config name
//! uciname!(wireless, radio0);
//! ```

use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

mod lexer;

// ============================================================================
// Case Transformation Functions
// ============================================================================

/// Convert any string to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let mut prev_lower = false;
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            if prev_lower || (i > 0 && chars.get(i + 1).map_or(false, |n| n.is_lowercase())) {
                result.push('_');
            }
            result.extend(c.to_lowercase());
            prev_lower = false;
        } else if *c == '-' || *c == ' ' {
            result.push('_');
            prev_lower = false;
        } else {
            result.push(*c);
            prev_lower = c.is_lowercase();
        }
    }
    result
}

/// Convert any string to SCREAMING_SNAKE_CASE
fn to_screaming_snake_case(s: &str) -> String {
    to_snake_case(s).to_uppercase()
}

/// Convert any string to camelCase
fn to_camel_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = false;
    let mut first = true;
    for c in s.chars() {
        if c == '_' || c == '-' || c == ' ' {
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else if first {
            result.extend(c.to_lowercase());
            first = false;
        } else {
            result.push(c);
        }
    }
    result
}

/// Convert any string to PascalCase
fn to_pascal_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = true;
    for c in s.chars() {
        if c == '_' || c == '-' || c == ' ' {
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

/// Convert to lowercase
fn to_lower(s: &str) -> String {
    s.to_lowercase()
}

/// Convert to UPPERCASE
fn to_upper(s: &str) -> String {
    s.to_uppercase()
}

// ============================================================================
// Parsing Structures
// ============================================================================

/// Represents a case transformation modifier
#[derive(Debug, Clone, Copy)]
enum CaseKind {
    #[allow(dead_code)]
    None,
    Snake,
    Screaming,
    Camel,
    Pascal,
    Lower,
    Upper,
}

impl CaseKind {
    fn apply(&self, s: &str) -> String {
        match self {
            CaseKind::None => s.to_string(),
            CaseKind::Snake => to_snake_case(s),
            CaseKind::Screaming => to_screaming_snake_case(s),
            CaseKind::Camel => to_camel_case(s),
            CaseKind::Pascal => to_pascal_case(s),
            CaseKind::Lower => to_lower(s),
            CaseKind::Upper => to_upper(s),
        }
    }

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "snake" => Ok(CaseKind::Snake),
            "screaming" => Ok(CaseKind::Screaming),
            "camel" => Ok(CaseKind::Camel),
            "pascal" => Ok(CaseKind::Pascal),
            "lower" => Ok(CaseKind::Lower),
            "upper" => Ok(CaseKind::Upper),
            _ => Err(format!("unknown case modifier: '{}'. Expected one of: snake, screaming, camel, pascal, lower, upper", s)),
        }
    }
}

/// A segment in the paste expression
#[derive(Debug)]
enum Segment {
    /// A literal string or identifier
    Literal(String),
    /// A transformed segment with case modifier
    Transformed(CaseKind, String),
    /// A concatenation group
    Concatenation(Vec<Segment>),
    /// An iteration segment (like $name in paste)
    Iteration(String, Option<CaseKind>),
}

impl Segment {
    fn eval(&self) -> String {
        match self {
            Segment::Literal(s) => s.clone(),
            Segment::Transformed(kind, s) => kind.apply(s),
            Segment::Concatenation(segments) => {
                segments.iter().map(|s| s.eval()).collect()
            }
            Segment::Iteration(name, case) => {
                let result = name.clone();
                if let Some(kind) = case {
                    kind.apply(&result)
                } else {
                    result
                }
            }
        }
    }
}

/// The complete paste input
struct PasteInput {
    segments: Vec<Segment>,
}

impl PasteInput {
    fn parse_from_tokens(input: TokenStream) -> Result<Self, String> {
        let mut segments = Vec::new();
        let mut tokens = input.into_iter().peekable();

        while let Some(token) = tokens.next() {
            match token {
                // Concatenation group (...) or {...}
                TokenTree::Group(group)
                    if group.delimiter() == Delimiter::Parenthesis
                        || group.delimiter() == Delimiter::Brace =>
                {
                    let inner_segments = Self::parse_inner_tokens(group.stream())?;
                    segments.push(Segment::Concatenation(inner_segments));
                }
                // Case modifier in brackets [snake], [screaming], etc.
                TokenTree::Group(group)
                    if group.delimiter() == Delimiter::Bracket =>
                {
                    let modifier_str: String =
                        group.stream().into_iter().map(|t| t.to_string()).collect();
                    let modifier_str = modifier_str.trim().to_string();

                    // Check if this is a simple modifier or a complex identifier pattern
                    if modifier_str.contains('$')
                        || modifier_str.split_whitespace().count() > 1
                        || (modifier_str.contains('_')
                            && !matches!(
                                modifier_str.as_str(),
                                "snake" | "screaming" | "camel" | "pascal" | "lower" | "upper"
                            ))
                    {
                        // Complex pattern like [set_ $name:lower]
                        let inner_segments = Self::parse_complex_bracket(&modifier_str)?;
                        segments.push(Segment::Concatenation(inner_segments));
                    } else {
                        // Simple case modifier
                        let kind = CaseKind::from_str(&modifier_str)?;

                        // Expect a string literal or identifier after the modifier
                        let value = match tokens.next() {
                            Some(TokenTree::Literal(lit)) => {
                                let s = lit.to_string();
                                if s.starts_with('"') && s.ends_with('"') {
                                    s[1..s.len() - 1].to_string()
                                } else {
                                    s
                                }
                            }
                            Some(TokenTree::Ident(ident)) => ident.to_string(),
                            _ => {
                                return Err(format!(
                                    "expected string literal or identifier after case modifier '{}'",
                                    modifier_str
                                ))
                            }
                        };

                        segments.push(Segment::Transformed(kind, value));
                    }
                }
                // For all other tokens, preserve them exactly as they are
                _ => {
                    segments.push(Segment::Literal(token.to_string()));
                }
            }
        }

        Ok(PasteInput { segments })
    }

    fn parse_inner_tokens(input: TokenStream) -> Result<Vec<Segment>, String> {
        let mut segments = Vec::new();
        let mut tokens = input.into_iter().peekable();

        while let Some(token) = tokens.next() {
            match token {
                TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket => {
                    let modifier_str: String =
                        group.stream().into_iter().map(|t| t.to_string()).collect();
                    let modifier_str = modifier_str.trim().to_string();

                    if modifier_str.contains('$') || modifier_str.split_whitespace().count() > 1 {
                        let inner_segments = Self::parse_complex_bracket(&modifier_str)?;
                        segments.push(Segment::Concatenation(inner_segments));
                    } else {
                        let kind = CaseKind::from_str(&modifier_str)?;

                        let value = match tokens.next() {
                            Some(TokenTree::Literal(lit)) => {
                                let s = lit.to_string();
                                if s.starts_with('"') && s.ends_with('"') {
                                    s[1..s.len() - 1].to_string()
                                } else {
                                    s
                                }
                            }
                            Some(TokenTree::Ident(ident)) => ident.to_string(),
                            _ => {
                                return Err(format!(
                                    "expected string literal or identifier after case modifier '{}'",
                                    modifier_str
                                ))
                            }
                        };

                        segments.push(Segment::Transformed(kind, value));
                    }
                }
                _ => {
                    segments.push(Segment::Literal(token.to_string()));
                }
            }
        }

        Ok(segments)
    }

    fn parse_complex_bracket(input: &str) -> Result<Vec<Segment>, String> {
        let mut segments = Vec::new();
        let mut chars = input.chars().peekable();
        let mut current = String::new();

        while let Some(ch) = chars.next() {
            match ch {
                '$' => {
                    if !current.is_empty() {
                        segments.push(Segment::Literal(current.clone()));
                        current.clear();
                    }
                    // Read the variable name
                    let mut var_name = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            var_name.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    // Check for case modifier after colon
                    let case_kind = if let Some(&':') = chars.peek() {
                        chars.next(); // consume ':'
                        let mut case_str = String::new();
                        while let Some(&c) = chars.peek() {
                            if c.is_alphabetic() {
                                case_str.push(c);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        Some(CaseKind::from_str(&case_str)?)
                    } else {
                        None
                    };

                    segments.push(Segment::Iteration(var_name, case_kind));
                }
                _ => {
                    current.push(ch);
                }
            }
        }

        if !current.is_empty() {
            segments.push(Segment::Literal(current));
        }

        Ok(segments)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn tokens_from_str(s: &str) -> TokenStream {
    s.parse().unwrap_or_else(|e| {
        format!("compile_error!(\"{}\")", e)
            .parse()
            .unwrap_or_else(|_| TokenStream::new())
    })
}

fn compile_error(msg: &str) -> TokenStream {
    format!("compile_error!(\"{}\")", msg).parse().unwrap()
}

fn compile_date() -> String {
    // Use a static date string since CARGO_PKG_DATE is not available
    // In a real build system, this could be set via build.rs
    env!("CARGO_PKG_VERSION").to_string()
}

fn compile_time() -> String {
    // Use version as timestamp approximation
    // In a real build system, this could be set via build.rs
    "00:00:00".to_string()
}

fn compile_timestamp() -> u64 {
    // Simple timestamp from date/time
    format!("{}{}", compile_date().replace("-", ""), compile_time().replace(":", ""))
        .parse()
        .unwrap_or(0)
}

fn concatenate_with_prefix_awareness(segments: &[Segment]) -> String {
    segments.iter().map(|s| s.eval()).collect()
}

fn parse_fn_parts(input: TokenStream) -> (Vec<TokenTree>, String, Vec<TokenTree>, Option<TokenTree>) {
    let mut tokens: Vec<TokenTree> = input.into_iter().collect();
    let mut prefix = Vec::new();
    let mut fn_name = String::new();
    let mut rest = Vec::new();
    let mut body = None;
    let mut i = 0;

    while i < tokens.len() {
        if let TokenTree::Ident(ident) = &tokens[i] {
            if ident.to_string() == "fn" {
                prefix.extend(tokens.drain(..=i));
                break;
            }
        }
        i += 1;
    }

    i = 0;
    while i < tokens.len() {
        if let TokenTree::Ident(ident) = &tokens[i] {
            fn_name = ident.to_string();
            rest.extend(tokens.drain(..=i));
            break;
        }
        i += 1;
    }

    i = 0;
    while i < tokens.len() {
        if let TokenTree::Group(g) = &tokens[i] {
            if g.delimiter() == Delimiter::Brace {
                body = Some(tokens.remove(i));
                rest.extend(tokens.drain(..i));
                break;
            }
        }
        rest.push(tokens.remove(i));
    }

    (prefix, fn_name, rest, body)
}

// ============================================================================
// Paste Macros
// ============================================================================

/// Create an identifier by pasting segments together with optional case transformations.
///
/// This macro concatenates multiple segments at compile time to produce a single
/// identifier. Each segment can optionally have a case transformation applied.
///
/// # Syntax
///
/// - Simple concatenation: `(A B C)` or `{A B C}` concatenates A, B, and C
/// - Case modifiers: `[snake]`, `[screaming]`, `[camel]`, `[pascal]`, `[lower]`, `[upper]`
/// - Nested concatenation: `(A (B C))` or `{A {B C}}`
/// - Mixed: `(prefix [snake]"HelloWorld")` or `{prefix [snake]"HelloWorld"}`
/// - Iteration: `$name` or `$name:case`
///
/// # Case Modifiers
///
/// - `[snake]` - convert to snake_case
/// - `[screaming]` - convert to SCREAMING_SNAKE_CASE
/// - `[camel]` - convert to camelCase
/// - `[pascal]` - convert to PascalCase
/// - `[lower]` - convert to lowercase
/// - `[upper]` - convert to UPPERCASE
///
/// # Examples
///
/// ```ignore
/// use ocfg_macros::paste_ident;
///
/// // Simple concatenation
/// let x = paste_ident!((get value)); // produces: getvalue
/// let y = paste_ident!({get value}); // produces: getvalue
///
/// // With case transformations
/// let z = paste_ident!((get [snake]"HelloWorld")); // produces: get_hello_world
/// let w = paste_ident!({get [snake]"HelloWorld"}); // produces: get_hello_world
///
/// // Multiple segments
/// let a = paste_ident!(([pascal]"my_field" Getter)); // produces: MyFieldGetter
/// ```
#[proc_macro]
pub fn paste_ident(input: TokenStream) -> TokenStream {
    // Use lexer to validate input structure
    let _lexer_result = lexer::Lexer::extract_bracket_groups(input.clone());

    let parsed = match PasteInput::parse_from_tokens(input) {
        Ok(p) => p,
        Err(e) => return compile_error(&e),
    };

    let combined: String = parsed.segments.iter().map(|s| s.eval()).collect();

    if combined.is_empty() {
        return compile_error("paste_ident! produced empty identifier");
    }

    if !combined.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return compile_error(&format!("invalid identifier: '{}'. Identifiers must contain only alphanumeric characters and underscores", combined));
    }

    if !combined.starts_with(|c: char| c.is_alphabetic() || c == '_') {
        return compile_error(&format!("identifier cannot start with digit: '{}'", combined));
    }

    combined.parse().unwrap_or_else(|_| {
        compile_error(&format!("failed to create identifier: '{}'", combined))
    })
}

/// Paste macro that handles entire code blocks with bracket syntax.
///
/// This macro processes the entire input, replacing bracket groups [<...>] with
/// concatenated identifiers while preserving the rest of the code structure.
///
/// # Syntax
///
/// - `[<content>]` - Replace with concatenated identifier from content
/// - Everything else is preserved as-is
///
/// # Examples
///
/// ```ignore
/// paste! {
///     pub fn [<set_ $name:lower>](mut self) -> Self {
///         self.flags |= Self::$name;
///         self
///     }
/// }
/// ```
#[proc_macro]
pub fn paste(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let mut output = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        match &tokens[i] {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket => {
                let content = group.stream();
                let content_str = content.to_string();

                if content_str.starts_with('<') && content_str.ends_with('>') {
                    let inner_content = content_str[1..content_str.len() - 1].trim();
                    let inner_content = inner_content.replace(' ', "");

                    let parsed = match PasteInput::parse_complex_bracket(&inner_content) {
                        Ok(p) => p,
                        Err(e) => return compile_error(&e),
                    };

                    let combined: String = concatenate_with_prefix_awareness(&parsed);

                    if combined.is_empty() {
                        return compile_error("paste! produced empty identifier");
                    }

                    if !combined.chars().all(|c: char| c.is_alphanumeric() || c == '_') {
                        return compile_error(&format!("invalid identifier: '{}'", combined));
                    }

                    let ident_token = format!("{} ", combined);
                    if let Ok(mut stream) = ident_token.parse::<TokenStream>() {
                        stream = stream
                            .into_iter()
                            .take_while(|t| t.to_string().trim() != "")
                            .collect();
                        output.extend(stream);
                    } else {
                        return compile_error(&format!("invalid identifier: '{}'", combined));
                    }
                } else {
                    output.push(tokens[i].clone());
                }

                i += 1;
            }
            TokenTree::Group(group) => {
                let processed = process_group(group.stream());
                let new_group = Group::new(group.delimiter(), processed);
                output.push(TokenTree::Group(new_group));
                i += 1;
            }
            _ => {
                output.push(tokens[i].clone());
                i += 1;
            }
        }
    }

    let mut result = TokenStream::new();
    for token in output {
        result.extend(Some(token));
    }
    result
}

fn process_group(stream: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut output = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        match &tokens[i] {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket => {
                let content = group.stream();
                let content_str = content.to_string();

                if content_str.starts_with('<') && content_str.ends_with('>') {
                    let inner_content = content_str[1..content_str.len() - 1].trim();
                    let inner_content = inner_content.replace(' ', "");

                    let parsed = match PasteInput::parse_complex_bracket(&inner_content) {
                        Ok(p) => p,
                        Err(e) => return compile_error(&e),
                    };

                    let combined: String = concatenate_with_prefix_awareness(&parsed);

                    if combined.is_empty() {
                        return compile_error("paste! produced empty identifier");
                    }

                    if !combined.chars().all(|c: char| c.is_alphanumeric() || c == '_') {
                        return compile_error(&format!("invalid identifier: '{}'", combined));
                    }

                    let ident_token = format!("{} ", combined);
                    if let Ok(mut stream) = ident_token.parse::<TokenStream>() {
                        stream = stream
                            .into_iter()
                            .take_while(|t| t.to_string().trim() != "")
                            .collect();
                        output.extend(stream);
                    } else {
                        return compile_error(&format!("invalid identifier: '{}'", combined));
                    }
                } else {
                    output.push(tokens[i].clone());
                }

                i += 1;
            }
            TokenTree::Group(group) => {
                let processed = process_group(group.stream());
                let new_group = Group::new(group.delimiter(), processed);
                output.push(TokenTree::Group(new_group));
                i += 1;
            }
            _ => {
                output.push(tokens[i].clone());
                i += 1;
            }
        }
    }

    let mut result = TokenStream::new();
    for token in output {
        result.extend(Some(token));
    }
    result
}

/// Concatenate segments into a string literal.
///
/// Similar to paste_ident! but produces a string literal instead of an identifier.
///
/// # Examples
///
/// ```ignore
/// let s = paste_str!((hello [snake]"World")); // produces: "hello_world"
/// ```
#[proc_macro]
pub fn paste_str(input: TokenStream) -> TokenStream {
    let parsed = match PasteInput::parse_from_tokens(input) {
        Ok(p) => p,
        Err(e) => return compile_error(&e),
    };

    let combined: String = parsed.segments.iter().map(|s| s.eval()).collect();
    format!("\"{}\"", combined).parse().unwrap()
}

// ============================================================================
// Debug Macros
// ============================================================================

/// Captures file, line, column as a struct.
///
/// # Usage
/// ```ignore
/// let loc = dbg_loc!();
/// println!("{}:{}:{}", loc.file, loc.line, loc.column);
/// ```
#[proc_macro]
pub fn dbg_loc(_input: TokenStream) -> TokenStream {
    tokens_from_str(
        r#"
        {
            #[derive(Debug, Clone, Copy)]
            struct DbgLoc { file: &'static str, line: u32, column: u32 }
            DbgLoc { file: file!(), line: line!(), column: column!() }
        }
    "#,
    )
}

/// Creates a full debug context with compile-time information.
///
/// # Usage
/// ```ignore
/// let ctx = dbg_ctx!();
/// println!("{}", ctx.full());
/// ```
#[proc_macro]
pub fn dbg_ctx(_input: TokenStream) -> TokenStream {
    let date = compile_date();
    let time = compile_time();
    let timestamp = compile_timestamp();
    let code = format!(
        r#"
        {{
            #[derive(Debug, Clone)]
            struct DbgCtx {{
                file: &'static str, line: u32, column: u32, module: &'static str,
                compile_date: &'static str, compile_time: &'static str, compile_timestamp: u64,
            }}
            impl DbgCtx {{
                #[inline] fn location(&self) -> String {{ format!("{{}}:{{}}:{{}}", self.file, self.line, self.column) }}
                #[inline] fn full(&self) -> String {{ format!("[{{}} {{}}] {{}}:{{}}:{{}} in {{}}", self.compile_date, self.compile_time, self.file, self.line, self.column, self.module) }}
            }}
            DbgCtx {{
                file: file!(), line: line!(), column: column!(), module: module_path!(),
                compile_date: "{}", compile_time: "{}", compile_timestamp: {}u64,
            }}
        }}
    "#,
        date, time, timestamp
    );
    tokens_from_str(&code)
}

/// Quick debug print with location information.
///
/// # Usage
/// ```ignore
/// dbg_here!();                              // prints: [date time file:line:col] HERE
/// dbg_here!("checkpoint");                  // prints: [date time file:line:col] checkpoint
/// dbg_here!("Error: {}", err);              // prints: [date time file:line:col] Error: value
/// dbg_here!("{} - {}", variant, message);   // prints: [date time file:line:col] variant - message
/// dbg_here!(x, y);                          // prints: [date time file:line:col] x=val, y=val
/// ```
#[proc_macro]
pub fn dbg_here(input: TokenStream) -> TokenStream {
    let date = compile_date();
    let time = compile_time();
    
    // Use lexer to detect format strings
    let mut lexer = lexer::Lexer::new();
    let _ = lexer.tokenize(input.clone());
    
    let tokens: Vec<TokenTree> = input.into_iter().collect();

    if tokens.is_empty() {
        let code = format!(
            r#"{{ eprintln!("[{{}} {{}} {{}}:{{}}:{{}}] HERE", "{}", "{}", file!(), line!(), column!()); }}"#,
            date, time
        );
        tokens_from_str(&code)
    } else if tokens.len() == 1 {
        if let TokenTree::Literal(lit) = &tokens[0] {
            let msg = lit.to_string();
            // Check if it's a format string (contains {})
            if msg.contains("{}") {
                let code = format!(
                    r#"{{ eprintln!("[{{}} {{}} {{}}:{{}}:{{}}] {}", "{}", "{}", file!(), line!(), column!()); }}"#,
                    msg, date, time
                );
                tokens_from_str(&code)
            } else {
                let code = format!(
                    r#"{{ eprintln!("[{{}} {{}} {{}}:{{}}:{{}}] {{}}", "{}", "{}", file!(), line!(), column!(), {}); }}"#,
                    date, time, msg
                );
                tokens_from_str(&code)
            }
        } else {
            let expr = tokens[0].to_string();
            let code = format!(
                r#"{{ eprintln!("[{{}} {{}} {{}}:{{}}:{{}}] {} = {{:?}}", "{}", "{}", file!(), line!(), column!(), {}); }}"#,
                expr, date, time, expr
            );
            tokens_from_str(&code)
        }
    } else {
        // Use lexer to check for format string pattern
        if lexer.has_format_string_pattern() {
            // If lexer detected a format string, use it directly
            let all_tokens: String = tokens.iter().map(|t| t.to_string()).collect();
            let code = format!(
                r#"{{ eprintln!("[{{}} {{}} {{}}:{{}}:{{}}] {}", "{}", "{}", file!(), line!(), column!()); }}"#,
                all_tokens, date, time
            );
            tokens_from_str(&code)
        } else {
            // Treat as expressions
            let mut prints = String::new();
            let mut first = true;
            for token in &tokens {
                if let TokenTree::Punct(p) = token {
                    if p.as_char() == ',' {
                        continue;
                    }
                }
                if !first {
                    prints.push_str(", ");
                }
                prints.push_str(&format!("{} = {{:?}}", token));
                first = false;
            }
            let args: Vec<String> = tokens
                .iter()
                .filter(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                .map(|t| t.to_string())
                .collect();
            let args_str = args.join(", ");
            let code = format!(
                r#"{{ eprintln!("[{{}} {{}} {{}}:{{}}:{{}}] {}", "{}", "{}", file!(), line!(), column!(), {}); }}"#,
                prints, date, time, args_str
            );
            tokens_from_str(&code)
        }
    }
}

/// Simple debug print with location information (no date/time prefix).
/// This is a simpler version that just prints file:line and the message.
///
/// # Usage
/// ```ignore
/// dbg_loc!();                    // prints: [file:line:col] HERE
/// dbg_loc!("checkpoint");        // prints: [file:line:col] checkpoint
/// dbg_loc!("Error: {}", err);    // prints: [file:line:col] Error: value
/// ```
#[proc_macro]
pub fn dbg_loc_simple(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();

    if tokens.is_empty() {
        let code = r#"{{ eprintln!("[{{}}:{{}}:{{}}] HERE", file!(), line!(), column!()); }}"#;
        tokens_from_str(code)
    } else if tokens.len() == 1 {
        if let TokenTree::Literal(lit) = &tokens[0] {
            let msg = lit.to_string();
            // Check if it's a format string (contains {})
            if msg.contains("{}") {
                let code = format!(
                    r#"{{ eprintln!("[{{}}:{{}}:{{}}] {}", file!(), line!(), column!()); }}"#,
                    msg
                );
                tokens_from_str(&code)
            } else {
                let code = format!(
                    r#"{{ eprintln!("[{{}}:{{}}:{{}}] {{}}", file!(), line!(), column!(), {}); }}"#,
                    msg
                );
                tokens_from_str(&code)
            }
        } else {
            let expr = tokens[0].to_string();
            let code = format!(
                r#"{{ eprintln!("[{{}}:{{}}:{{}}] {} = {{:?}}", file!(), line!(), column!(), {}); }}"#,
                expr, expr
            );
            tokens_from_str(&code)
        }
    } else {
        // Check if first token is a literal string (potential format string)
        if let TokenTree::Literal(lit) = &tokens[0] {
            let msg = lit.to_string();
            if msg.contains("{}") {
                // Treat as format string with remaining tokens as arguments
                let args: Vec<String> = tokens
                    .iter()
                    .skip(1)
                    .filter(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                    .map(|t| t.to_string())
                    .collect();
                let args_str = args.join(", ");
                let code = format!(
                    r#"{{ eprintln!("[{{}}:{{}}:{{}}] {}", file!(), line!(), column!(), {}); }}"#,
                    msg, args_str
                );
                tokens_from_str(&code)
            } else {
                // Treat as simple message followed by expressions
                let mut prints = String::new();
                let mut first = true;
                for token in &tokens {
                    if let TokenTree::Punct(p) = token {
                        if p.as_char() == ',' {
                            continue;
                        }
                    }
                    if !first {
                        prints.push_str(", ");
                    }
                    prints.push_str(&format!("{} = {{:?}}", token));
                    first = false;
                }
                let args: Vec<String> = tokens
                    .iter()
                    .filter(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                    .map(|t| t.to_string())
                    .collect();
                let args_str = args.join(", ");
                let code = format!(
                    r#"{{ eprintln!("[{{}}:{{}}:{{}}] {}", file!(), line!(), column!(), {}); }}"#,
                    prints, args_str
                );
                tokens_from_str(&code)
            }
        } else {
            // All tokens are expressions
            let mut prints = String::new();
            let mut first = true;
            for token in &tokens {
                if let TokenTree::Punct(p) = token {
                    if p.as_char() == ',' {
                        continue;
                    }
                }
                if !first {
                    prints.push_str(", ");
                }
                prints.push_str(&format!("{} = {{:?}}", token));
                first = false;
            }
            let args: Vec<String> = tokens
                .iter()
                .filter(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                .map(|t| t.to_string())
                .collect();
            let args_str = args.join(", ");
            let code = format!(
                r#"{{ eprintln!("[{{}}:{{}}:{{}}] {}", file!(), line!(), column!(), {}); }}"#,
                prints, args_str
            );
            tokens_from_str(&code)
        }
    }
}

/// Log with high-resolution timestamp.
///
/// # Usage
/// ```ignore
/// dbg_time!("processing started");
/// dbg_time!("value = {}", x);
/// ```
#[proc_macro]
pub fn dbg_time(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();

    if tokens.is_empty() {
        let code = r#"{{ eprintln!("[{{:?}}] timestamp", std::time::Instant::now()); }}"#;
        tokens_from_str(code)
    } else {
        let args_str = tokens.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(" ");
        let code = format!(
            "eprintln!(\"[{{:?}}] {}\", std::time::Instant::now())",
            args_str
        );
        tokens_from_str(&code)
    }
}

/// Creates a named debug scope that prints entry and exit with timing.
///
/// # Usage
/// ```ignore
/// fn process() {
///     dbg_scope!("process");
///     // ... code ...
/// } // prints exit with elapsed time when scope ends
/// ```
#[proc_macro]
pub fn dbg_scope(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let name = if let Some(TokenTree::Literal(lit)) = tokens.first() {
        lit.to_string().trim_matches('"').to_string()
    } else if let Some(TokenTree::Ident(ident)) = tokens.first() {
        ident.to_string()
    } else {
        "scope".to_string()
    };
    let date = compile_date();
    let time = compile_time();
    let code = format!(
        r#"
        {{
            struct _DbgScopeGuard {{ name: &'static str, file: &'static str, line: u32, start: std::time::Instant }}
            impl Drop for _DbgScopeGuard {{
                fn drop(&mut self) {{
                    eprintln!("[{{}} {{}} {{}}:{{}}] EXIT {{}} ({{:.3?}})", "{}", "{}", self.file, self.line, self.name, self.start.elapsed());
                }}
            }}
            let _scope_guard = _DbgScopeGuard {{ name: "{}", file: file!(), line: line!(), start: std::time::Instant::now() }};
            eprintln!("[{{}} {{}} {{}}:{{}}] ENTER {}", "{}", "{}", file!(), line!(), "{}");
        }}
    "#,
        date, time, name, name, date, time, name
    );
    tokens_from_str(&code)
}

/// Attribute macro that wraps a function with debug entry/exit logging.
///
/// # Usage
/// ```ignore
/// #[dbg_fn]
/// fn my_function(x: i32) -> i32 { x * 2 }
/// // Automatically logs entry and exit with timing
/// ```
#[proc_macro_attribute]
pub fn dbg_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let (prefix, fn_name, rest, body) = parse_fn_parts(item.clone());
    let date = compile_date();
    let time = compile_time();

    if fn_name.is_empty() || body.is_none() {
        return item;
    }

    let body_group = body.unwrap();
    let body_content = if let TokenTree::Group(g) = &body_group {
        g.stream()
            .into_iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        return item;
    };

    let prefix_str: String = prefix
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let rest_str: String = rest
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let code = format!(
        r#"
        {} {} {{
            struct _DbgFnGuard {{ name: &'static str, start: std::time::Instant }}
            impl Drop for _DbgFnGuard {{
                fn drop(&mut self) {{ eprintln!("[{} {} {{}}:{{}}] EXIT {{}} ({{:.3?}})", file!(), line!(), self.name, self.start.elapsed()); }}
            }}
            let _fn_guard = _DbgFnGuard {{ name: "{}", start: std::time::Instant::now() }};
            eprintln!("[{} {} {{}}:{{}}] ENTER {}", file!(), line!(), "{}");
            {}
        }}
    "#,
        prefix_str, rest_str, date, time, fn_name, date, time, fn_name, fn_name, body_content
    );
    tokens_from_str(&code)
}

/// Returns compile-time build information.
///
/// # Usage
/// ```ignore
/// let info = compile_info!();
/// println!("Built: {} {}", info.date, info.time);
/// ```
#[proc_macro]
pub fn compile_info(_input: TokenStream) -> TokenStream {
    let date = compile_date();
    let time = compile_time();
    let timestamp = compile_timestamp();
    let code = format!(
        r#"
        {{
            #[derive(Debug, Clone, Copy)]
            struct CompileInfo {{ date: &'static str, time: &'static str, timestamp: u64 }}
            impl CompileInfo {{ #[inline] fn datetime(&self) -> String {{ format!("{{}} {{}}", self.date, self.time) }} }}
            CompileInfo {{ date: "{}", time: "{}", timestamp: {}u64 }}
        }}
    "#,
        date, time, timestamp
    );
    tokens_from_str(&code)
}

/// Current location as string.
///
/// # Usage
/// ```ignore
/// let loc = loc_str!();
/// println!("{}", loc); // prints: file:line:column
/// ```
#[proc_macro]
pub fn loc_str(_input: TokenStream) -> TokenStream {
    tokens_from_str(r#"format!("{}:{}:{}", file!(), line!(), column!())"#)
}

/// Current module path.
///
/// # Usage
/// ```ignore
/// let mod_path = mod_str!();
/// println!("{}", mod_path);
/// ```
#[proc_macro]
pub fn mod_str(_input: TokenStream) -> TokenStream {
    tokens_from_str(r#"module_path!().to_string()"#)
}

/// Captures enclosing function name.
///
/// Note: This is a best-effort approximation using standard Rust macros.
/// For accurate function name capture, consider using the `std::any::type_name`
/// or external crates like `function_name`.
///
/// # Usage
/// ```ignore
/// let name = fn_name!();
/// println!("In function: {}", name);
/// ```
#[proc_macro]
pub fn fn_name(_input: TokenStream) -> TokenStream {
    tokens_from_str(r#""<function_name>".to_string()"#)
}

// ============================================================================
// OpenWrt-Specific Macros
// ============================================================================

/// Generate UCI (Unified Configuration Interface) config option names.
///
/// This macro helps generate standardized UCI config option names for OpenWrt.
///
/// # Syntax
///
/// ```ignore
/// uciname!(config_type, section_name, option_name)
/// ```
///
/// # Examples
///
/// ```ignore
/// // Generates: wireless.radio0
/// uciname!(wireless, radio0);
///
/// // Generates: network.lan.ipaddr
/// uciname!(network, lan, ipaddr);
/// ```
#[proc_macro]
pub fn uciname(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let parts: Vec<String> = tokens
        .iter()
        .filter_map(|t| match t {
            TokenTree::Ident(ident) => Some(ident.to_string()),
            TokenTree::Literal(lit) => {
                let s = lit.to_string();
                if s.starts_with('"') && s.ends_with('"') {
                    Some(s[1..s.len() - 1].to_string())
                } else {
                    Some(s)
                }
            }
            _ => None,
        })
        .collect();

    if parts.is_empty() || parts.len() > 3 {
        return compile_error("uciname! expects 1-3 identifiers or string literals");
    }

    let combined = parts.join(".");
    format!("\"{}\"", combined).parse().unwrap()
}

/// Generate UCI config path identifiers.
///
/// Similar to uciname! but produces identifiers instead of string literals.
///
/// # Syntax
///
/// ```ignore
/// ucipath!(config_type, section_name, option_name)
/// ```
///
/// # Examples
///
/// ```ignore
/// // Generates: wireless_radio0
/// ucipath!(wireless, radio0);
///
/// // Generates: network_lan_ipaddr
/// ucipath!(network, lan, ipaddr);
/// ```
#[proc_macro]
pub fn ucipath(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let parts: Vec<String> = tokens
        .iter()
        .filter_map(|t| match t {
            TokenTree::Ident(ident) => Some(to_snake_case(&ident.to_string())),
            TokenTree::Literal(lit) => {
                let s = lit.to_string();
                if s.starts_with('"') && s.ends_with('"') {
                    Some(to_snake_case(&s[1..s.len() - 1]))
                } else {
                    Some(to_snake_case(&s))
                }
            }
            _ => None,
        })
        .collect();

    if parts.is_empty() || parts.len() > 3 {
        return compile_error("ucipath! expects 1-3 identifiers or string literals");
    }

    let combined = parts.join("_");
    combined.parse().unwrap_or_else(|_| {
        compile_error(&format!("failed to create identifier: '{}'", combined))
    })
}
