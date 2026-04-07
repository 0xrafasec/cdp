//! URL path glob matching for CDP policy rules.
//!
//! Supports two wildcard forms:
//! - `*`  — matches exactly one path segment (no `/` characters)
//! - `**` — matches zero or more path segments (including their delimiters)
//!
//! Both path and pattern are normalized before matching: leading and trailing
//! slashes are ignored and empty segments (from consecutive slashes) are
//! discarded.

/// Normalize a URL path or glob pattern into its non-empty segments.
///
/// `/repos/foo/` → `["repos", "foo"]`
/// `/`           → `[]`
/// `""`          → `[]`
fn segments(s: &str) -> Vec<&str> {
    s.split('/').filter(|seg| !seg.is_empty()).collect()
}

/// Returns `true` if `path` matches `pattern` using CDP glob semantics.
///
/// - Literal segment: must match exactly (case-sensitive).
/// - `*`: matches exactly one path segment (no `/`).
/// - `**`: matches zero or more path segments.
///
/// Both `path` and `pattern` are normalized (leading/trailing slashes and
/// empty segments ignored) before matching.
pub fn path_matches_glob(path: &str, pattern: &str) -> bool {
    let path_segs = segments(path);
    let pat_segs = segments(pattern);
    matches_segs(&path_segs, &pat_segs)
}

/// Returns `true` if `path` matches **any** of the given `patterns`.
///
/// Returns `false` immediately if `patterns` is empty.
pub fn any_glob_matches(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| path_matches_glob(path, p))
}

/// Core iterative matcher operating on pre-split segment slices.
///
/// Uses an explicit work-list (stack of `(path_idx, pat_idx)` pairs) to avoid
/// recursion-depth blowup and to handle `**` without exponential branching.
/// A visited set prevents re-processing the same `(path_idx, pat_idx)` state,
/// which ensures O(n * m) worst-case behavior even for pathological patterns
/// like `**/**/**/**`.
fn matches_segs(path: &[&str], pat: &[&str]) -> bool {
    // Stack entries: (path segment index, pattern segment index).
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    // Visited set to prevent redundant re-exploration of the same state.
    let mut visited: std::collections::HashSet<(usize, usize)> =
        std::collections::HashSet::new();

    while let Some((pi, qi)) = stack.pop() {
        if !visited.insert((pi, qi)) {
            // Already explored this state.
            continue;
        }

        match (path.get(pi), pat.get(qi)) {
            // Both exhausted — full match.
            (None, None) => return true,

            // Pattern exhausted but path still has segments — no match on this
            // branch; continue with other stack entries.
            (Some(_), None) => continue,

            // Path exhausted but pattern still has segments.
            // Only valid if all remaining pattern segments are `**` (each `**`
            // can match zero segments).
            (None, Some(_)) => {
                if pat[qi..].iter().all(|s| *s == "**") {
                    return true;
                }
                // Otherwise this branch fails.
                continue;
            }

            // Both have segments remaining.
            (Some(&pseg), Some(&qseg)) => {
                if qseg == "**" {
                    // `**` matches zero segments: advance only the pattern.
                    stack.push((pi, qi + 1));
                    // `**` matches one segment: advance path and keep `**`.
                    stack.push((pi + 1, qi));
                } else if qseg == "*" {
                    // `*` matches exactly the current path segment.
                    stack.push((pi + 1, qi + 1));
                } else if qseg == pseg {
                    // Literal match.
                    stack.push((pi + 1, qi + 1));
                }
                // Otherwise this branch fails; try remaining stack entries.
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- path_matches_glob ---

    #[test]
    fn exact_match() {
        assert!(path_matches_glob("/repos/foo/pulls", "/repos/foo/pulls"));
    }

    #[test]
    fn single_wildcard_match() {
        assert!(path_matches_glob("/repos/myrepo/pulls", "/repos/*/pulls"));
    }

    #[test]
    fn single_wildcard_no_match_multiple_segments() {
        // `*` must not span a `/`; `/repos/a/b/pulls` has an extra segment.
        assert!(!path_matches_glob("/repos/a/b/pulls", "/repos/*/pulls"));
    }

    #[test]
    fn single_wildcard_no_match_wrong_suffix() {
        assert!(!path_matches_glob("/repos/myrepo/issues", "/repos/*/pulls"));
    }

    #[test]
    fn double_wildcard_suffix_root() {
        // `/repos/**` must match `/repos` itself (zero extra segments).
        assert!(path_matches_glob("/repos", "/repos/**"));
    }

    #[test]
    fn double_wildcard_suffix_one_segment() {
        assert!(path_matches_glob("/repos/foo", "/repos/**"));
    }

    #[test]
    fn double_wildcard_suffix_many_segments() {
        assert!(path_matches_glob("/repos/foo/bar", "/repos/**"));
    }

    #[test]
    fn double_wildcard_middle_zero_segments() {
        // `/repos/**/hooks` matches `/repos/hooks` (zero middle segments).
        assert!(path_matches_glob("/repos/hooks", "/repos/**/hooks"));
    }

    #[test]
    fn double_wildcard_middle_one_segment() {
        assert!(path_matches_glob("/repos/foo/hooks", "/repos/**/hooks"));
    }

    #[test]
    fn double_wildcard_middle_many_segments() {
        assert!(path_matches_glob("/repos/foo/bar/hooks", "/repos/**/hooks"));
    }

    #[test]
    fn double_wildcard_middle_wrong_suffix() {
        assert!(!path_matches_glob("/repos/foo/pulls", "/repos/**/hooks"));
    }

    #[test]
    fn root_path_matches_root_pattern() {
        assert!(path_matches_glob("/", "/"));
    }

    #[test]
    fn root_path_empty_string() {
        assert!(path_matches_glob("", ""));
    }

    #[test]
    fn no_match_different_prefix() {
        assert!(!path_matches_glob("/repos/foo", "/users/bar"));
    }

    #[test]
    fn trailing_slash_normalization_path() {
        assert!(path_matches_glob("/repos/foo/", "/repos/foo"));
    }

    #[test]
    fn trailing_slash_normalization_pattern() {
        assert!(path_matches_glob("/repos/foo", "/repos/foo/"));
    }

    #[test]
    fn trailing_slash_normalization_both() {
        assert!(path_matches_glob("/repos/foo/", "/repos/foo/"));
    }

    #[test]
    fn mixed_wildcards() {
        // `/repos/*/issues/**` should match `/repos/myrepo/issues/123/comments`
        assert!(path_matches_glob(
            "/repos/myrepo/issues/123/comments",
            "/repos/*/issues/**"
        ));
    }

    #[test]
    fn mixed_wildcards_no_extra_segment_for_star() {
        // The `*` must match exactly one segment; `**` can be zero.
        assert!(path_matches_glob(
            "/repos/myrepo/issues",
            "/repos/*/issues/**"
        ));
    }

    #[test]
    fn double_wildcard_at_start_zero_prefix() {
        // `**/hooks` matches `/hooks` (zero leading segments).
        assert!(path_matches_glob("/hooks", "**/hooks"));
    }

    #[test]
    fn double_wildcard_at_start_one_prefix() {
        assert!(path_matches_glob("/repos/hooks", "**/hooks"));
    }

    #[test]
    fn double_wildcard_at_start_many_prefix() {
        assert!(path_matches_glob("/a/b/c/hooks", "**/hooks"));
    }

    #[test]
    fn double_wildcard_at_start_wrong_suffix() {
        assert!(!path_matches_glob("/a/b/c/pulls", "**/hooks"));
    }

    #[test]
    fn bare_double_wildcard_matches_everything() {
        assert!(path_matches_glob("/repos/foo/bar/baz", "**"));
        assert!(path_matches_glob("/", "**"));
        assert!(path_matches_glob("", "**"));
        assert!(path_matches_glob("/single", "**"));
    }

    // --- any_glob_matches ---

    #[test]
    fn any_glob_matches_first_pattern() {
        let patterns = vec!["/repos/foo".to_string(), "/users/bar".to_string()];
        assert!(any_glob_matches("/repos/foo", &patterns));
    }

    #[test]
    fn any_glob_matches_second_pattern() {
        let patterns = vec!["/repos/foo".to_string(), "/users/bar".to_string()];
        assert!(any_glob_matches("/users/bar", &patterns));
    }

    #[test]
    fn any_glob_matches_no_match() {
        let patterns = vec!["/repos/foo".to_string(), "/users/bar".to_string()];
        assert!(!any_glob_matches("/admin/settings", &patterns));
    }

    #[test]
    fn any_glob_matches_empty_patterns_returns_false() {
        assert!(!any_glob_matches("/repos/foo", &[]));
    }

    #[test]
    fn any_glob_matches_with_wildcards() {
        let patterns = vec!["/repos/**".to_string(), "/users/*/profile".to_string()];
        assert!(any_glob_matches("/repos/foo/bar", &patterns));
        assert!(any_glob_matches("/users/alice/profile", &patterns));
        assert!(!any_glob_matches("/admin/settings", &patterns));
    }

    // --- additional edge cases ---

    #[test]
    fn consecutive_double_wildcards() {
        // Pathological pattern: should not blow up and should still be correct.
        assert!(path_matches_glob(
            "/a/b/c/d/e",
            "**/**/**"
        ));
    }

    #[test]
    fn star_does_not_match_empty_segment() {
        // A `*` in the pattern requires at least one path segment to consume.
        assert!(!path_matches_glob("/repos", "/repos/*/"));
    }

    #[test]
    fn literal_no_partial_match() {
        assert!(!path_matches_glob("/repositories/foo", "/repos/foo"));
    }

    #[test]
    fn case_sensitive_matching() {
        assert!(!path_matches_glob("/Repos/foo", "/repos/foo"));
    }
}
