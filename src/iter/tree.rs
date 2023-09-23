// SPDX-License-Identifier: CC0-1.0

//! Abstract Trees
//!
//! This module provides the [`TreeLike`] trait which represents a node in a
//! tree, and several iterators over trees whose nodes implement this trait.
//!

use crate::prelude::*;
use crate::sync::Arc;

/// Abstract node of a tree.
///
/// Tracks the arity (out-degree) of a node, which is the only thing that
/// is needed for iteration purposes.
pub enum Tree<T> {
    /// Combinator with no children.
    Nullary,
    /// Combinator with one child.
    Unary(T),
    /// Combinator with two children.
    Binary(T, T),
    /// Combinator with more than two children.
    Nary(Arc<[T]>),
}

/// A trait for any structure which has the shape of a Miniscript tree.
///
/// As a general rule, this should be implemented on references to nodes,
/// rather than nodes themselves, because it provides algorithms that
/// assume copying is cheap.
///
/// To implement this trait, you only need to implement the [`TreeLike::as_node`]
/// method, which will usually be very mechanical. Everything else is provided.
/// However, to avoid allocations, it may make sense to also implement
/// [`TreeLike::n_children`] and [`TreeLike::nth_child`] because the default
/// implementations will allocate vectors for n-ary nodes.
pub trait TreeLike: Clone + Sized {
    /// Interpret the node as an abstract node.
    fn as_node(&self) -> Tree<Self>;

    /// Accessor for the number of children this node has.
    fn n_children(&self) -> usize {
        match self.as_node() {
            Tree::Nullary => 0,
            Tree::Unary(..) => 1,
            Tree::Binary(..) => 2,
            Tree::Nary(children) => children.len(),
        }
    }

    /// Accessor for the nth child of the node, if a child with that index exists.
    fn nth_child(&self, n: usize) -> Option<Self> {
        match (n, self.as_node()) {
            (_, Tree::Nullary) => None,
            (0, Tree::Unary(sub)) => Some(sub),
            (_, Tree::Unary(..)) => None,
            (0, Tree::Binary(sub, _)) => Some(sub),
            (1, Tree::Binary(_, sub)) => Some(sub),
            (_, Tree::Binary(..)) => None,
            (n, Tree::Nary(children)) => children.get(n).cloned(),
        }
    }

    /// Obtains an iterator of all the nodes rooted at the node, in pre-order.
    fn pre_order_iter(self) -> PreOrderIter<Self> { PreOrderIter { stack: vec![self] } }

    /// Obtains a verbose iterator of all the nodes rooted at the DAG, in pre-order.
    ///
    /// See the documentation of [`VerbosePreOrderIter`] for more information about what
    /// this does. Essentially, if you find yourself using [`Self::pre_order_iter`] and
    /// then adding a stack to manually track which items and their children have been
    /// yielded, you may be better off using this iterator instead.
    fn verbose_pre_order_iter(self) -> VerbosePreOrderIter<Self> {
        VerbosePreOrderIter { stack: vec![PreOrderIterItem::initial(self, None)], index: 0 }
    }

    /// Obtains an iterator of all the nodes rooted at the DAG, in post order.
    ///
    /// Each node is only yielded once, at the leftmost position that it
    /// appears in the DAG.
    fn post_order_iter(self) -> PostOrderIter<Self> {
        PostOrderIter { index: 0, stack: vec![IterStackItem::unprocessed(self, None)] }
    }
}

/// Element stored internally on the stack of a [`PostOrderIter`].
///
/// This is **not** the type that is yielded by the [`PostOrderIter`];
/// in fact, this type is not even exported.
#[derive(Clone, Debug)]
struct IterStackItem<T> {
    /// The element on the stack
    elem: T,
    /// Whether we have dealt with this item (and pushed its children,
    /// if any) yet.
    processed: bool,
    /// If the item has been processed, the index of its children.
    child_indices: Vec<usize>,
    /// Whether the element is a left- or right-child of its parent.
    parent_stack_idx: Option<usize>,
}

impl<T: TreeLike> IterStackItem<T> {
    /// Constructor for a new stack item with a given element and relationship
    /// to its parent.
    fn unprocessed(elem: T, parent_stack_idx: Option<usize>) -> Self {
        IterStackItem {
            processed: false,
            child_indices: Vec::with_capacity(elem.n_children()),
            parent_stack_idx,
            elem,
        }
    }
}

/// Iterates over a DAG in _post order_.
///
/// That means nodes are yielded in the order (left child, right child, parent).
#[derive(Clone, Debug)]
pub struct PostOrderIter<T> {
    /// The index of the next item to be yielded
    index: usize,
    /// A stack of elements to be yielded; each element is a node, then its left
    /// and right children (if they exist and if they have been yielded already)
    stack: Vec<IterStackItem<T>>,
}

/// A set of data yielded by a `PostOrderIter`.
pub struct PostOrderIterItem<T> {
    /// The actual node data
    pub node: T,
    /// The index of this node (equivalent to if you'd called `.enumerate()` on
    /// the iterator)
    pub index: usize,
    /// The indices of this node's children.
    pub child_indices: Vec<usize>,
}

impl<T: TreeLike> Iterator for PostOrderIter<T> {
    type Item = PostOrderIterItem<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut current = self.stack.pop()?;

        if !current.processed {
            current.processed = true;

            // When we first encounter an item, it is completely unknown; it is
            // nominally the next item to be yielded, but it might have children,
            // and if so, they come first
            let current_stack_idx = self.stack.len();
            let n_children = current.elem.n_children();
            self.stack.push(current);
            for idx in (0..n_children).rev() {
                self.stack.push(IterStackItem::unprocessed(
                    self.stack[current_stack_idx].elem.nth_child(idx).unwrap(),
                    Some(current_stack_idx),
                ));
            }
            self.next()
        } else {
            // The second time we encounter an item, we have dealt with its children,
            // updated the child indices for this item, and are now ready to yield it
            // rather than putting it back in the stack.
            //
            // Before yielding though, we must the item's parent's child indices with
            // this item's index.
            if let Some(idx) = current.parent_stack_idx {
                self.stack[idx].child_indices.push(self.index);
            }

            self.index += 1;
            Some(PostOrderIterItem {
                node: current.elem,
                index: self.index - 1,
                child_indices: current.child_indices,
            })
        }
    }
}

/// Iterates over a [`TreeLike`] in _pre order_.
///
/// Unlike the post-order iterator, this one does not keep track of indices
/// (this would be impractical since when we yield a node we have not yet
/// yielded its children, so we cannot know their indices). If you do need
/// the indices for some reason, the best strategy may be to run the
/// post-order iterator, collect into a vector, then iterate through that
/// backward.
#[derive(Clone, Debug)]
pub struct PreOrderIter<T> {
    /// A stack of elements to be yielded. As items are yielded, their right
    /// children are put onto the stack followed by their left, so that the
    /// appropriate one will be yielded on the next iteration.
    stack: Vec<T>,
}

impl<T: TreeLike> Iterator for PreOrderIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // This algorithm is _significantly_ simpler than the post-order one,
        // mainly because we don't care about child indices.
        let top = self.stack.pop()?;
        match top.as_node() {
            Tree::Nullary => {}
            Tree::Unary(next) => self.stack.push(next),
            Tree::Binary(left, right) => {
                self.stack.push(right);
                self.stack.push(left);
            }
            Tree::Nary(children) => {
                self.stack.extend(children.iter().rev().cloned());
            }
        }
        Some(top)
    }
}

/// Iterates over a [`TreeLike`] in "verbose pre order", yielding extra state changes.
///
/// This yields nodes followed by their children, followed by the node *again*
/// after each child. This means that each node will be yielded a total of
/// (n+1) times, where n is its number of children.
///
/// The different times that a node is yielded can be distinguished by looking
/// at the [`PreOrderIterItem::n_children_yielded`]  (which, in particular,
/// will be 0 on the first yield) and [`PreOrderIterItem::is_complete`] (which
/// will be true on the last yield) fields of the yielded item.
#[derive(Clone, Debug)]
pub struct VerbosePreOrderIter<T> {
    /// A stack of elements to be yielded. As items are yielded, their right
    /// children are put onto the stack followed by their left, so that the
    /// appropriate one will be yielded on the next iteration.
    stack: Vec<PreOrderIterItem<T>>,
    /// The index of the next item to be yielded.
    ///
    /// Note that unlike the [`PostOrderIter`], this value is not monotonic
    /// and not equivalent to just using `enumerate` on the iterator, because
    /// elements may be yielded multiple times.
    index: usize,
}

impl<T: TreeLike + Clone> Iterator for VerbosePreOrderIter<T> {
    type Item = PreOrderIterItem<T>;

    fn next(&mut self) -> Option<Self::Item> {
        // This algorithm is still simpler than the post-order one, because while
        // we care about node indices, we don't care about their childrens' indices.
        let mut top = self.stack.pop()?;

        // If this is the first time we're be yielding this element, set its index.
        if top.n_children_yielded == 0 {
            top.index = self.index;
            self.index += 1;
        }
        // Push the next child.
        let n_children = top.node.n_children();
        if top.n_children_yielded < n_children {
            self.stack.push(top.clone().increment(n_children));
            let child = top.node.nth_child(top.n_children_yielded).unwrap();
            self.stack
                .push(PreOrderIterItem::initial(child, Some(top.node.clone())));
        }

        // Then yield the element.
        Some(top)
    }
}

/// A set of data yielded by a [`VerbosePreOrderIter`].
#[derive(Clone, Debug)]
pub struct PreOrderIterItem<T> {
    /// The actual element being yielded.
    pub node: T,
    /// The parent of this node. `None` for the initial node, but will be
    /// populated for all other nodes.
    pub parent: Option<T>,
    /// The index when the element was first yielded.
    pub index: usize,
    /// How many of this item's children have been yielded.
    ///
    /// This can also be interpreted as a count of how many times this
    /// item has been yielded before.
    pub n_children_yielded: usize,
    /// Whether this item is done (will not be yielded again).
    pub is_complete: bool,
}

impl<T: TreeLike + Clone> PreOrderIterItem<T> {
    /// Creates a `PreOrderIterItem` which yields a given element for the first time.
    ///
    /// Marks the index as 0. The index must be manually set before yielding.
    fn initial(node: T, parent: Option<T>) -> Self {
        PreOrderIterItem {
            is_complete: node.n_children() == 0,
            node,
            parent,
            index: 0,
            n_children_yielded: 0,
        }
    }

    /// Creates a `PreOrderIterItem` which yields a given element again.
    fn increment(self, n_children: usize) -> Self {
        PreOrderIterItem {
            node: self.node,
            index: self.index,
            parent: self.parent,
            n_children_yielded: self.n_children_yielded + 1,
            is_complete: self.n_children_yielded + 1 == n_children,
        }
    }
}
