// ============================================================================
// Advanced Lexer for Macro Processing
// ============================================================================

//! An advanced lexer for parsing macro input with support for format strings,
//! macro invocations, and complex token patterns in the ocfg project.

use proc_macro::{Delimiter, TokenStream, TokenTree};
use std::collections::HashMap;

// ============================================================================
// Token Categories - Enhanced categorization system
// ============================================================================

/// Enhanced token categories for advanced macro parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenCategory {
    /// Identifiers (variables, function names, etc.)
    Identifier,
    /// Literals (strings, numbers, etc.)
    Literal,
    /// Format string literals (containing {})
    FormatString,
    /// Operators (=, +, -, *, /, etc.)
    Operator,
    /// Punctuation (, ; : . etc.)
    Punctuation,
    /// Group delimiters ((), [], {})
    GroupDelimiter,
    /// Keywords (fn, pub, mut, etc.)
    Keyword,
    /// Dollar sign for macro variables
    Dollar,
    /// Colon for case modifiers
    Colon,
    /// Macro invocations (format!, stringify!, etc.)
    Macro,
    /// Whitespace (spaces, tabs)
    Whitespace,
    /// Unknown/invalid
    Unknown,
}

impl TokenCategory {
    /// Check if this token could be part of a format string
    pub fn is_format_string_part(&self) -> bool {
        matches!(self, TokenCategory::Literal | TokenCategory::FormatString | TokenCategory::Identifier)
    }

    /// Check if this is a string-like token
    pub fn is_string_like(&self) -> bool {
        matches!(self, TokenCategory::Literal | TokenCategory::FormatString)
    }
}

// ============================================================================
// Lexer Token - Enhanced token with detailed information
// ============================================================================

/// Enhanced token representation with format string detection
#[derive(Debug, Clone)]
pub struct LexerToken {
    /// The raw token string
    pub raw: String,
    /// Token category
    pub category: TokenCategory,
    /// Original proc_macro token
    pub token: Option<TokenTree>,
    /// Token position in the original stream
    pub position: usize,
    /// Whether this is a format string (contains {})
    pub is_format: bool,
    /// Nested group depth (for parentheses, brackets, etc.)
    pub depth: usize,
}

impl LexerToken {
    pub fn new(raw: String, category: TokenCategory, position: usize) -> Self {
        let is_format = category == TokenCategory::FormatString || 
                        (category == TokenCategory::Literal && raw.contains("{}"));

        Self {
            raw,
            category,
            token: None,
            position,
            is_format,
            depth: 0,
        }
    }

    pub fn with_token(mut self, token: TokenTree) -> Self {
        self.token = Some(token);
        self
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    /// Check if this token contains format placeholders
    pub fn has_placeholders(&self) -> bool {
        self.is_format || self.raw.contains("{}")
    }

    /// Extract format string content (without quotes)
    pub fn as_string_content(&self) -> Option<String> {
        if self.category.is_string_like() {
            let content = self.raw.trim_matches('"').trim_matches('\'').to_string();
            Some(content)
        } else {
            None
        }
    }
}

// ============================================================================
// Lexer - Main tokenization engine with advanced parsing
// ============================================================================

#[derive(Clone)]
pub struct Lexer {
    tokens: Vec<LexerToken>,
    keywords: HashMap<String, TokenCategory>,
    macros: HashMap<String, TokenCategory>,
}

impl Lexer {
    pub fn new() -> Self {
        let mut keywords = HashMap::new();

        // Rust keywords
        keywords.insert("fn".to_string(), TokenCategory::Keyword);
        keywords.insert("pub".to_string(), TokenCategory::Keyword);
        keywords.insert("mut".to_string(), TokenCategory::Keyword);
        keywords.insert("self".to_string(), TokenCategory::Keyword);
        keywords.insert("Self".to_string(), TokenCategory::Keyword);
        keywords.insert("struct".to_string(), TokenCategory::Keyword);
        keywords.insert("impl".to_string(), TokenCategory::Keyword);
        keywords.insert("let".to_string(), TokenCategory::Keyword);
        keywords.insert("if".to_string(), TokenCategory::Keyword);
        keywords.insert("else".to_string(), TokenCategory::Keyword);
        keywords.insert("while".to_string(), TokenCategory::Keyword);
        keywords.insert("for".to_string(), TokenCategory::Keyword);
        keywords.insert("loop".to_string(), TokenCategory::Keyword);
        keywords.insert("break".to_string(), TokenCategory::Keyword);
        keywords.insert("continue".to_string(), TokenCategory::Keyword);
        keywords.insert("return".to_string(), TokenCategory::Keyword);
        keywords.insert("match".to_string(), TokenCategory::Keyword);
        keywords.insert("true".to_string(), TokenCategory::Keyword);
        keywords.insert("false".to_string(), TokenCategory::Keyword);

        let mut macros = HashMap::new();
        
        // Common Rust macros
        macros.insert("format".to_string(), TokenCategory::Macro);
        macros.insert("format_args".to_string(), TokenCategory::Macro);
        macros.insert("println".to_string(), TokenCategory::Macro);
        macros.insert("eprintln".to_string(), TokenCategory::Macro);
        macros.insert("stringify".to_string(), TokenCategory::Macro);
        macros.insert("concat".to_string(), TokenCategory::Macro);
        macros.insert("env".to_string(), TokenCategory::Macro);
        macros.insert("option_env".to_string(), TokenCategory::Macro);
        macros.insert("include_str".to_string(), TokenCategory::Macro);
        macros.insert("include_bytes".to_string(), TokenCategory::Macro);

        Self {
            tokens: Vec::new(),
            keywords,
            macros,
        }
    }

    /// Tokenize a TokenStream with advanced parsing
    pub fn tokenize(&mut self, input: TokenStream) -> Result<(), String> {
        self.tokens.clear();
        let input_tokens: Vec<TokenTree> = input.into_iter().collect();
        let mut depth = 0;

        for (position, token) in input_tokens.into_iter().enumerate() {
            let lexer_token = self.process_token(&token, position, depth)?;
            
            // Update depth based on the token
            depth = match lexer_token.raw.as_str() {
                "(" | "[" | "{" => depth + 1,
                ")" | "]" | "}" => depth.saturating_sub(1),
                _ => depth,
            };
            
            self.tokens.push(lexer_token);
        }

        Ok(())
    }

    /// Process a single token with enhanced categorization
    fn process_token(&self, token: &TokenTree, position: usize, depth: usize) -> Result<LexerToken, String> {
        match token {
            TokenTree::Ident(ident) => {
                let ident_str = ident.to_string();
                let category = if let Some(&keyword_cat) = self.keywords.get(&ident_str) {
                    keyword_cat
                } else if let Some(&macro_cat) = self.macros.get(&ident_str) {
                    macro_cat
                } else if ident_str == "$" {
                    TokenCategory::Dollar
                } else if ident_str == ":" {
                    TokenCategory::Colon
                } else {
                    TokenCategory::Identifier
                };

                Ok(LexerToken::new(ident_str, category, position)
                    .with_token(token.clone())
                    .with_depth(depth))
            }
            TokenTree::Punct(punct) => {
                let punct_str = punct.to_string();
                let category = match punct_str.as_str() {
                    "=" | "+" | "-" | "*" | "/" | "%" | "!" | "&" | "|" | "^" | "~" | "<" | ">"
                    | "?" | "@" => TokenCategory::Operator,
                    "," | ";" | "#" | "`" | "\\" => TokenCategory::Punctuation,
                    ":" => TokenCategory::Colon,
                    "$" => TokenCategory::Dollar,
                    "." => TokenCategory::Operator,
                    _ => TokenCategory::Unknown,
                };

                Ok(LexerToken::new(punct_str, category, position)
                    .with_token(token.clone())
                    .with_depth(depth))
            }
            TokenTree::Literal(lit) => {
                let lit_str = lit.to_string();
                let category = if lit_str.contains("{}") {
                    TokenCategory::FormatString
                } else {
                    TokenCategory::Literal
                };

                Ok(LexerToken::new(lit_str, category, position)
                    .with_token(token.clone())
                    .with_depth(depth))
            }
            TokenTree::Group(group) => {
                // For groups, we create a delimiter token
                let delimiter_str = match group.delimiter() {
                    Delimiter::Parenthesis => "(",
                    Delimiter::Brace => "{",
                    Delimiter::Bracket => "[",
                    Delimiter::None => "",
                };

                Ok(LexerToken::new(
                    delimiter_str.to_string(),
                    TokenCategory::GroupDelimiter,
                    position,
                )
                .with_token(token.clone())
                .with_depth(depth))
            }
        }
    }

    /// Get the tokens
    pub fn tokens(&self) -> &[LexerToken] {
        &self.tokens
    }

    /// Consume tokens into a Vec
    pub fn into_tokens(self) -> Vec<LexerToken> {
        self.tokens
    }

    /// Find bracket groups (tokens between [ and ])
    pub fn find_bracket_groups(&self) -> Vec<Vec<&LexerToken>> {
        let mut groups = Vec::new();
        let mut current_group = Vec::new();
        let mut depth = 0;

        for token in &self.tokens {
            if token.category == TokenCategory::GroupDelimiter && token.raw == "[" {
                if depth == 0 {
                    current_group.clear();
                }
                depth += 1;
                current_group.push(token);
            } else if token.category == TokenCategory::GroupDelimiter && token.raw == "]" {
                current_group.push(token);
                depth -= 1;
                if depth == 0 && !current_group.is_empty() {
                    groups.push(current_group.clone());
                    current_group.clear();
                }
            } else if depth > 0 {
                current_group.push(token);
            }
        }

        groups
    }

    /// Extract bracket groups as strings
    pub fn extract_bracket_groups(input: TokenStream) -> Result<Vec<String>, String> {
        let mut lexer = Lexer::new();
        lexer.tokenize(input)?;
        let groups = lexer.find_bracket_groups();

        let mut result = Vec::new();
        for group in groups {
            if group.len() > 2 {
                let content: String = group[1..group.len()-1]
                    .iter()
                    .map(|t| t.raw.clone())
                    .collect();
                result.push(content);
            }
        }

        Ok(result)
    }

    /// Parse a format string and its arguments
    pub fn parse_format_string(&self, start_idx: usize) -> Result<(String, Vec<String>), String> {
        if start_idx >= self.tokens.len() {
            return Err("Invalid start index".to_string());
        }

        let format_token = &self.tokens[start_idx];
        let format_str = format_token.as_string_content()
            .ok_or("Token is not a string")?;

        // Count placeholders in format string
        let placeholder_count = format_str.matches("{}").count();

        // Collect the next N non-punctuation tokens as arguments
        let mut args = Vec::new();
        let mut arg_count = 0;
        
        for i in (start_idx + 1)..self.tokens.len() {
            if arg_count >= placeholder_count {
                break;
            }
            
            let token = &self.tokens[i];
            if !matches!(token.category, TokenCategory::Punctuation) {
                args.push(token.raw.clone());
                arg_count += 1;
            }
        }

        Ok((format_str, args))
    }

    /// Detect if the token stream contains a format string pattern
    pub fn has_format_string_pattern(&self) -> bool {
        self.tokens.iter().any(|t| t.has_placeholders())
    }

    /// Get the first format string and its arguments
    pub fn get_first_format_string(&self) -> Option<(String, Vec<String>)> {
        for (i, token) in self.tokens.iter().enumerate() {
            if token.has_placeholders() {
                if let Ok((format_str, args)) = self.parse_format_string(i) {
                    return Some((format_str, args));
                }
            }
        }
        None
    }

    /// Find all tokens of a specific category
    pub fn find_by_category(&self, category: TokenCategory) -> Vec<&LexerToken> {
        self.tokens
            .iter()
            .filter(|t| t.category == category)
            .collect()
    }

    /// Find tokens by their raw string value
    pub fn find_by_value(&self, value: &str) -> Vec<&LexerToken> {
        self.tokens
            .iter()
            .filter(|t| t.raw == value)
            .collect()
    }

    /// Get tokens as a formatted string
    pub fn to_string(&self) -> String {
        self.tokens.iter()
            .map(|t| t.raw.clone())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Clear the lexer state
    pub fn clear(&mut self) {
        self.tokens.clear();
    }

    /// Get token at specific position
    pub fn get_token(&self, index: usize) -> Option<&LexerToken> {
        self.tokens.get(index)
    }
}
