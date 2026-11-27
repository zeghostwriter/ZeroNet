//! Xray-compatible bounded randomness.

use rand::Rng;

/// Xray's `crypto.RandBetween`.
///
/// Note the two quirks this must reproduce exactly, because fragment sizes
/// derived from it are observable on the wire:
///
/// * arguments are swapped when inverted;
/// * a span of 0 **or 1** returns `from`, so `"1-2"` always yields 1;
/// * otherwise the result is `from + rand(0..span)`, i.e. `to` is exclusive.
pub fn rand_between(from: i64, to: i64) -> i64 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    let span = to - from;
    if span == 0 || span == 1 {
        return from;
    }
    from + rand::thread_rng().gen_range(0..span)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bounds_are_exact() {
        assert_eq!(rand_between(5, 5), 5);
    }

    #[test]
    fn span_of_one_returns_lower_bound() {
        // Matches Xray: "1-2" is always 1, never 2.
        for _ in 0..50 {
            assert_eq!(rand_between(1, 2), 1);
        }
    }

    #[test]
    fn inverted_bounds_are_swapped() {
        for _ in 0..50 {
            let v = rand_between(200, 100);
            assert!((100..200).contains(&v), "got {v}");
        }
    }

    #[test]
    fn upper_bound_is_exclusive() {
        for _ in 0..200 {
            let v = rand_between(100, 200);
            assert!((100..200).contains(&v), "got {v}");
        }
    }
}
