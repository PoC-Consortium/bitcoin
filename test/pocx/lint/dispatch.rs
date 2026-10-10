// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

use std::path::PathBuf;

/// Keep all original linters except the reviewed locale-reference policy copy.
/// A missing owned checker remains a failing Python invocation.
pub fn python_linter(original: PathBuf) -> PathBuf {
    if original.file_name().and_then(|name| name.to_str()) == Some("lint-locale-dependence.py") {
        original
            .parent().expect("lint directory")
            .parent().expect("test directory")
            .join("pocx/lint/locale_dependence.py")
    } else {
        original
    }
}

#[cfg(test)]
mod tests {
    use super::python_linter;
    use std::path::PathBuf;

    #[test]
    fn only_locale_checker_is_dispatched() {
        for name in ["lint-python.py", "lint-files.py", "lint-locale.py"] {
            let original = PathBuf::from("/source/test/lint").join(name);
            assert_eq!(python_linter(original.clone()), original);
        }
        assert_eq!(
            python_linter(PathBuf::from("/source/test/lint/lint-locale-dependence.py")),
            PathBuf::from("/source/test/pocx/lint/locale_dependence.py")
        );
        assert_eq!(
            python_linter(PathBuf::from("test/lint/lint-locale-dependence.py")),
            PathBuf::from("test/pocx/lint/locale_dependence.py")
        );
    }
}
