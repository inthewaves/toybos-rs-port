use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq)]
pub struct TreeIdx(usize);

const ROOT_IDX: usize = 0;

impl TreeIdx {
    pub fn root_idx() -> Self {
        TreeIdx(ROOT_IDX)
    }

    pub fn is_root(self) -> bool {
        self.0 == ROOT_IDX
    }
}

/// A HashMap-based tree that uses an auto-incrementing integer ID as node "pointers" (`TreeIdx`).
/// Using integers as pointers makes it cheap to copy around and store references (as long as there
/// is a reference to a tree).
///
/// Note: Removal is not supported (although easy to do)
#[derive(Debug)]
pub struct MapTree<T> {
    all_nodes: HashMap<TreeIdx, Node<T>>,
    autoincrement_idx: TreeIdx,
}

impl<T> Default for MapTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MapTree<T> {
    pub fn new_with_root(rootValue: T) -> Self {
        let mut map: HashMap<TreeIdx, Node<T>> = HashMap::new();
        map.insert(
            TreeIdx::root_idx(),
            Node {
                idx: TreeIdx::root_idx(),
                value: rootValue,
                parent: None,
                children: vec![],
            },
        );

        Self {
            all_nodes: map,
            autoincrement_idx: TreeIdx(1),
        }
    }

    pub fn new() -> Self {
        let map: HashMap<TreeIdx, Node<T>> = HashMap::new();
        Self {
            all_nodes: map,
            autoincrement_idx: TreeIdx::root_idx(),
        }
    }

    /// Returns a reference to the value corresponding to the given tree index.
    pub fn get(&self, index: &TreeIdx) -> Option<&Node<T>> {
        self.all_nodes.get(index)
    }

    /// Returns a reference to root node.
    pub fn get_root(&self) -> Option<&Node<T>> {
        self.all_nodes.get(&TreeIdx(ROOT_IDX))
    }

    pub fn get_mut(&mut self, index: &TreeIdx) -> Option<&mut Node<T>> {
        self.all_nodes.get_mut(index)
    }

    pub fn get_mut_root(&mut self) -> Option<&mut Node<T>> {
        self.all_nodes.get_mut(&TreeIdx(ROOT_IDX))
    }

    pub fn add(&mut self, new: T, parent_idx: &TreeIdx) -> TreeIdx {
        let map = &mut self.all_nodes;

        let current_idx = self.autoincrement_idx;

        if let Some(parent_node) = map.get_mut(parent_idx) {
            if current_idx != *parent_idx {
                parent_node.children.push(current_idx);
            }
        }

        map.insert(
            current_idx,
            Node {
                idx: if map.is_empty() {
                    TreeIdx::root_idx()
                } else {
                    current_idx
                },
                value: new,
                parent: if map.is_empty() {
                    None
                } else {
                    Some(*parent_idx)
                },
                children: vec![],
            },
        );

        self.autoincrement_idx = TreeIdx(self.autoincrement_idx.0 + 1);
        current_idx
    }
}

#[derive(Debug, Clone)]
pub struct Node<T> {
    idx: TreeIdx,
    value: T,
    parent: Option<TreeIdx>,
    children: Vec<TreeIdx>,
}

impl<T> Node<T> {
    pub fn idx(&self) -> TreeIdx {
        self.idx
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub fn parent(&self) -> Option<TreeIdx> {
        self.parent
    }

    pub fn children(&self) -> &[TreeIdx] {
        &self.children
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_works_with_no_initial_node() {
        const root_string: &str = "I am root";
        let mut tree: MapTree<String> = MapTree::new();
        tree.add(String::from(root_string), &TreeIdx::root_idx());
        assert_eq!(root_string, tree.get(&TreeIdx(0)).unwrap().value);
        assert_eq!(root_string, tree.get_root().unwrap().value);
        assert!(tree.get(&TreeIdx(1)).is_none());

        const second: &str = "This is root's child";
        let new_idx = tree.add(String::from(second), &TreeIdx::root_idx());
        assert_eq!(1, new_idx.0);
        assert_eq!(root_string, tree.get(&TreeIdx(0)).unwrap().value);
        assert_eq!(root_string, tree.get_root().unwrap().value);
        let second_node = tree.get(&new_idx).unwrap();
        assert_eq!(second, second_node.value);
        assert_eq!(new_idx, second_node.idx);
    }

    #[test]
    fn mutation_works() {
        #[derive(Eq, PartialEq, Debug)]
        struct TestStruct {
            a: bool,
            b: i32,
        }

        let mut tree: MapTree<TestStruct> = MapTree::new();

        tree.add(TestStruct { a: false, b: 0 }, &TreeIdx::root_idx());
        assert_eq!(
            TestStruct { a: false, b: 0 },
            *tree.get_root().unwrap().value()
        );

        let root_mut = tree.get_mut_root();
        root_mut.unwrap().value_mut().b = 50;
        assert_eq!(
            TestStruct { a: false, b: 50 },
            *tree.get_root().unwrap().value()
        );

        // Add a child and mutate it
        let child_idx = tree.add(TestStruct { a: true, b: -1 }, &TreeIdx::root_idx());
        assert_eq!(
            TestStruct { a: true, b: -1 },
            *tree.get(&child_idx).unwrap().value()
        );
        let child_mut = tree.get_mut(&child_idx).unwrap();
        child_mut.value_mut().a = false;
        child_mut.value_mut().b = 34536;
        assert_eq!(
            TestStruct { a: false, b: 34536 },
            *tree.get(&child_idx).unwrap().value()
        );
    }

    #[test]
    fn insertion_works() {
        const root_string: &str = "I am root";
        let mut tree: MapTree<String> = MapTree::new_with_root(String::from(root_string));
        assert_eq!(root_string, tree.get(&TreeIdx(0)).unwrap().value);
        assert_eq!(root_string, tree.get_root().unwrap().value);
        assert!(tree.get(&TreeIdx(1)).is_none());

        let root_node = tree.get_root().unwrap();
        assert_eq!(0, root_node.children.len());

        const second: &str = "This is root's child";
        let new_idx = tree.add(String::from(second), &TreeIdx::root_idx());
        assert_eq!(1, new_idx.0);
        assert_eq!(root_string, tree.get(&TreeIdx(0)).unwrap().value);
        assert_eq!(root_string, tree.get_root().unwrap().value);
        let new_node = tree.get(&new_idx).unwrap();
        assert_eq!(second, new_node.value);
        assert_eq!(new_idx, new_node.idx);

        let root_node = tree.get_root().unwrap();
        assert_eq!(1, root_node.children.len());
        let second_node_idx_from_root = root_node.children.first().unwrap();
        assert_eq!(new_idx, *second_node_idx_from_root);
        let second_node_from_root = tree.get(second_node_idx_from_root).unwrap();
        assert_eq!(second, second_node_from_root.value);
        assert_eq!(root_node.idx, second_node_from_root.parent.unwrap());

        const third: &str = "This is another of root's child";
        let new_idx = tree.add(String::from(third), &TreeIdx::root_idx());
        assert_eq!(2, new_idx.0);
        assert_eq!(root_string, tree.get(&TreeIdx(0)).unwrap().value);
        assert_eq!(root_string, tree.get_root().unwrap().value);
        assert_eq!(third, tree.get(&new_idx).unwrap().value);

        let root_node = tree.get_root().unwrap();
        assert_eq!(2, root_node.children.len());
        let third_node_idx_from_root = root_node.children.last().unwrap();
        assert_eq!(new_idx, *third_node_idx_from_root);
        assert_eq!(third, tree.get(third_node_idx_from_root).unwrap().value);
    }
}
