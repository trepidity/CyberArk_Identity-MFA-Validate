/// Diff engine for SAML assertion comparison.
/// LCS-based line diff with character-level sub-diff and byte-level comparison.

#[derive(Debug, Clone)]
pub enum DiffLine {
    Same(String),
    Added(String),
    Removed(String),
    Changed {
        left: String,
        right: String,
        left_spans: Vec<(usize, usize)>,
        right_spans: Vec<(usize, usize)>,
    },
}

#[derive(Debug, Clone)]
pub struct DiffResult {
    pub lines: Vec<DiffLine>,
    pub left_total: usize,
    pub right_total: usize,
    pub diff_count: usize,
}

#[derive(Debug, Clone)]
pub struct ByteDiffRow {
    pub offset: usize,
    pub left_bytes: Vec<u8>,
    pub right_bytes: Vec<u8>,
    pub diffs: Vec<usize>,
}

/// LCS-based line diff with backtracking.
/// Post-processes adjacent Removed+Added pairs into Changed variants
/// with character-level sub-diff spans.
pub fn diff_lines(left: &str, right: &str) -> DiffResult {
    let left_lines: Vec<&str> = left.lines().collect();
    let right_lines: Vec<&str> = right.lines().collect();

    let left_total = left_lines.len();
    let right_total = right_lines.len();

    let m = left_lines.len();
    let n = right_lines.len();

    // Build LCS table
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if left_lines[i - 1] == right_lines[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to produce raw diff lines
    let mut raw: Vec<DiffLine> = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && left_lines[i - 1] == right_lines[j - 1] {
            raw.push(DiffLine::Same(left_lines[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            raw.push(DiffLine::Added(right_lines[j - 1].to_string()));
            j -= 1;
        } else {
            raw.push(DiffLine::Removed(left_lines[i - 1].to_string()));
            i -= 1;
        }
    }
    raw.reverse();

    // Pair adjacent Removed+Added into Changed
    let paired = pair_changes(raw);

    let diff_count = paired
        .iter()
        .filter(|l| !matches!(l, DiffLine::Same(_)))
        .count();

    DiffResult {
        lines: paired,
        left_total,
        right_total,
        diff_count,
    }
}

/// Pairs adjacent Removed+Added sequences into Changed variants.
fn pair_changes(input: Vec<DiffLine>) -> Vec<DiffLine> {
    let mut output: Vec<DiffLine> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match &input[i] {
            DiffLine::Removed(_) => {
                // Collect a run of Removed lines
                let mut removed_run: Vec<String> = Vec::new();
                while i < input.len() {
                    if let DiffLine::Removed(s) = &input[i] {
                        removed_run.push(s.clone());
                        i += 1;
                    } else {
                        break;
                    }
                }
                // Collect following Added lines
                let mut added_run: Vec<String> = Vec::new();
                while i < input.len() {
                    if let DiffLine::Added(s) = &input[i] {
                        added_run.push(s.clone());
                        i += 1;
                    } else {
                        break;
                    }
                }
                // Pair them up
                let pairs = removed_run.len().min(added_run.len());
                for k in 0..pairs {
                    let left = removed_run[k].clone();
                    let right = added_run[k].clone();
                    let (left_spans, right_spans) = char_diff_spans(&left, &right);
                    output.push(DiffLine::Changed {
                        left,
                        right,
                        left_spans,
                        right_spans,
                    });
                }
                // Emit leftovers
                for s in removed_run.into_iter().skip(pairs) {
                    output.push(DiffLine::Removed(s));
                }
                for s in added_run.into_iter().skip(pairs) {
                    output.push(DiffLine::Added(s));
                }
            }
            DiffLine::Added(_) => {
                if let DiffLine::Added(s) = &input[i] {
                    output.push(DiffLine::Added(s.clone()));
                }
                i += 1;
            }
            DiffLine::Same(_) => {
                if let DiffLine::Same(s) = &input[i] {
                    output.push(DiffLine::Same(s.clone()));
                }
                i += 1;
            }
            DiffLine::Changed { .. } => {
                output.push(input[i].clone());
                i += 1;
            }
        }
    }
    output
}

/// LCS on characters, returns character offset spans (not byte offsets)
/// for safe UTF-8 slicing indicating which characters differ.
fn char_diff_spans(left: &str, right: &str) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let left_chars: Vec<char> = left.chars().collect();
    let right_chars: Vec<char> = right.chars().collect();

    let m = left_chars.len();
    let n = right_chars.len();

    // Build LCS table
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if left_chars[i - 1] == right_chars[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to find which character positions are in the LCS
    let mut left_in_lcs = vec![false; m];
    let mut right_in_lcs = vec![false; n];

    let mut i = m;
    let mut j = n;
    while i > 0 && j > 0 {
        if left_chars[i - 1] == right_chars[j - 1] {
            left_in_lcs[i - 1] = true;
            right_in_lcs[j - 1] = true;
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }

    // Positions NOT in LCS are the differing positions
    let left_diffs: Vec<bool> = left_in_lcs.iter().map(|&b| !b).collect();
    let right_diffs: Vec<bool> = right_in_lcs.iter().map(|&b| !b).collect();

    let left_spans = collapse_spans(&left_diffs);
    let right_spans = collapse_spans(&right_diffs);

    (left_spans, right_spans)
}

/// Collapses a bool array into contiguous spans of `true` values.
/// Returns `(start, end)` pairs where end is exclusive.
fn collapse_spans(diffs: &[bool]) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut in_span = false;
    let mut start = 0;
    for (i, &d) in diffs.iter().enumerate() {
        if d && !in_span {
            start = i;
            in_span = true;
        } else if !d && in_span {
            spans.push((start, i));
            in_span = false;
        }
    }
    if in_span {
        spans.push((start, diffs.len()));
    }
    spans
}

/// Chunks both inputs into 16-byte rows and compares row by row.
/// Returns rows that exist in either input with per-byte diff positions.
pub fn diff_bytes(left: &[u8], right: &[u8]) -> Vec<ByteDiffRow> {
    const ROW_SIZE: usize = 16;
    let max_len = left.len().max(right.len());
    let num_rows = (max_len + ROW_SIZE - 1) / ROW_SIZE;

    let mut rows: Vec<ByteDiffRow> = Vec::with_capacity(num_rows);

    for row_idx in 0..num_rows {
        let offset = row_idx * ROW_SIZE;
        let left_end = (offset + ROW_SIZE).min(left.len());
        let right_end = (offset + ROW_SIZE).min(right.len());

        let left_bytes: Vec<u8> = if offset < left.len() {
            left[offset..left_end].to_vec()
        } else {
            Vec::new()
        };

        let right_bytes: Vec<u8> = if offset < right.len() {
            right[offset..right_end].to_vec()
        } else {
            Vec::new()
        };

        // Find byte positions (within the row) that differ
        let row_len = left_bytes.len().max(right_bytes.len());
        let mut diffs: Vec<usize> = Vec::new();
        for byte_pos in 0..row_len {
            let l = left_bytes.get(byte_pos).copied();
            let r = right_bytes.get(byte_pos).copied();
            if l != r {
                diffs.push(byte_pos);
            }
        }

        rows.push(ByteDiffRow {
            offset,
            left_bytes,
            right_bytes,
            diffs,
        });
    }

    rows
}

/// Returns only diff lines plus surrounding context lines.
/// Each entry is `(original_line_index, &DiffLine)`.
pub fn filter_diff_lines(result: &DiffResult, context: usize) -> Vec<(usize, &DiffLine)> {
    let lines = &result.lines;
    let n = lines.len();

    // Determine which line indices are "interesting" (non-Same)
    let mut include = vec![false; n];
    for (i, line) in lines.iter().enumerate() {
        if !matches!(line, DiffLine::Same(_)) {
            // Mark surrounding context
            let start = i.saturating_sub(context);
            let end = (i + context + 1).min(n);
            for k in start..end {
                include[k] = true;
            }
        }
    }

    lines
        .iter()
        .enumerate()
        .filter(|(i, _)| include[*i])
        .collect()
}

/// Returns only rows with differences.
/// Each entry is `(row_index, &ByteDiffRow)`.
pub fn filter_byte_diff(rows: &[ByteDiffRow]) -> Vec<(usize, &ByteDiffRow)> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| !row.diffs.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_text() {
        let result = diff_lines("hello\nworld", "hello\nworld");
        assert_eq!(result.diff_count, 0);
        assert_eq!(result.lines.len(), 2);
        assert!(matches!(result.lines[0], DiffLine::Same(_)));
    }

    #[test]
    fn test_added_line() {
        let result = diff_lines("hello", "hello\nworld");
        assert_eq!(result.left_total, 1);
        assert_eq!(result.right_total, 2);
        // One Same and one Added
        let added = result
            .lines
            .iter()
            .filter(|l| matches!(l, DiffLine::Added(_)))
            .count();
        assert_eq!(added, 1);
    }

    #[test]
    fn test_removed_line() {
        let result = diff_lines("hello\nworld", "hello");
        let removed = result
            .lines
            .iter()
            .filter(|l| matches!(l, DiffLine::Removed(_)))
            .count();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_changed_line() {
        let result = diff_lines("hello world", "hello rust");
        let changed = result
            .lines
            .iter()
            .filter(|l| matches!(l, DiffLine::Changed { .. }))
            .count();
        assert_eq!(changed, 1);
    }

    #[test]
    fn test_char_diff_spans_identical() {
        let (l, r) = char_diff_spans("abc", "abc");
        assert!(l.is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn test_char_diff_spans_different() {
        let (l, r) = char_diff_spans("abc", "axc");
        // 'b' vs 'x' differ
        assert!(!l.is_empty());
        assert!(!r.is_empty());
    }

    #[test]
    fn test_collapse_spans() {
        let diffs = vec![false, true, true, false, true];
        let spans = collapse_spans(&diffs);
        assert_eq!(spans, vec![(1, 3), (4, 5)]);
    }

    #[test]
    fn test_diff_bytes_identical() {
        let data = b"hello world";
        let rows = diff_bytes(data, data);
        let different: Vec<_> = rows.iter().filter(|r| !r.diffs.is_empty()).collect();
        assert!(different.is_empty());
    }

    #[test]
    fn test_diff_bytes_different() {
        let left = b"hello world!!!!";
        let right = b"hello WORLD!!!!";
        let rows = diff_bytes(left, right);
        let different = filter_byte_diff(&rows);
        assert!(!different.is_empty());
    }

    #[test]
    fn test_filter_diff_lines_context() {
        let result = diff_lines(
            "a\nb\nc\nd\ne",
            "a\nb\nX\nd\ne",
        );
        // Line index 2 changed; with context=1 we expect lines 1,2,3
        let filtered = filter_diff_lines(&result, 1);
        assert!(filtered.len() >= 3);
    }
}
