//! The order in which candidates are tested.
//!
//! A feed lists servers in whatever order its scraper found them, which in
//! practice means long runs of one kind: two hundred WebSocket nodes behind
//! the same CDN, then a block of REALITY nodes. When a filtering change has
//! just broken one family, testing in feed order burns the whole time budget
//! on that family before reaching anything that works.
//!
//! So candidates are bucketed by [`LinkClass`], each bucket is shuffled (so
//! repeated discoveries do not all hammer the same first few servers), and the
//! buckets are interleaved round-robin. Whatever family currently survives is
//! reached within the first handful of tests.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::link::LinkClass;

/// Interleave `items` across classes, shuffled within each class.
pub fn order_by_class<T, R, F>(items: Vec<T>, class_of: F, rng: &mut R) -> Vec<T>
where
    R: Rng + ?Sized,
    F: Fn(&T) -> LinkClass,
{
    let total = items.len();
    let mut buckets: Vec<Vec<T>> = LinkClass::ALL.iter().map(|_| Vec::new()).collect();
    for item in items {
        let class = class_of(&item);
        let index = LinkClass::ALL
            .iter()
            .position(|candidate| *candidate == class)
            .unwrap_or(LinkClass::ALL.len() - 1);
        buckets[index].push(item);
    }
    for bucket in &mut buckets {
        bucket.shuffle(rng);
        // Popping from the back is O(1); reversing once keeps the shuffled
        // order as the pop order.
        bucket.reverse();
    }
    let mut ordered = Vec::with_capacity(total);
    while ordered.len() < total {
        for bucket in &mut buckets {
            if let Some(item) = bucket.pop() {
                ordered.push(item);
            }
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn classes_are_interleaved_and_nothing_is_lost() {
        let mut items = Vec::new();
        for index in 0..10 {
            items.push((LinkClass::CdnTls, index));
        }
        for index in 0..3 {
            items.push((LinkClass::Reality, index));
        }
        items.push((LinkClass::XhttpExtra, 0));
        items.push((LinkClass::Other, 0));
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let ordered = order_by_class(items.clone(), |item| item.0, &mut rng);

        assert_eq!(ordered.len(), items.len());
        // The first round takes one from each class, in class order.
        let first: Vec<LinkClass> = ordered.iter().take(4).map(|item| item.0).collect();
        assert_eq!(first, LinkClass::ALL.to_vec());
        // Once the small classes run out the large one fills the tail.
        assert!(ordered[8..].iter().all(|item| item.0 == LinkClass::CdnTls));
        let mut sorted = ordered.clone();
        sorted.sort();
        let mut expected = items;
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn order_within_a_class_is_shuffled() {
        let items: Vec<(LinkClass, u32)> = (0..50).map(|index| (LinkClass::Other, index)).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let ordered = order_by_class(items.clone(), |item| item.0, &mut rng);
        assert_ne!(
            ordered, items,
            "fifty items should not come back in feed order"
        );
    }

    #[test]
    fn an_empty_input_is_an_empty_order() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let ordered = order_by_class(Vec::<(LinkClass, u8)>::new(), |item| item.0, &mut rng);
        assert!(ordered.is_empty());
    }
}
