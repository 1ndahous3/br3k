use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct UniqueResource<R, D>
where
    D: FnOnce(R),
{
    resource: Option<R>,
    deleter: Option<D>,
}

impl<R, D> UniqueResource<R, D>
where
    D: FnOnce(R),
{
    pub fn new(resource: R, deleter: D) -> Self {
        Self {
            resource: Some(resource),
            deleter: Some(deleter),
        }
    }

    pub fn get(&self) -> &R {
        self.resource.as_ref().expect("Resource already taken")
    }

    pub fn into_inner(mut self) -> R {
        self.resource.take().expect("Resource already taken")
    }

    pub fn release(mut self) -> R {
        self.deleter.take(); // Prevent `Drop` from running
        self.into_inner()
    }
}

impl<R, D> PartialEq<R> for UniqueResource<R, D>
where
    R: PartialEq,
    D: FnOnce(R),
{
    fn eq(&self, other: &R) -> bool {
        self.resource.as_ref() == Some(other)
    }
}

impl<R, D> Deref for UniqueResource<R, D>
where
    D: FnOnce(R),
{
    type Target = R;

    fn deref(&self) -> &Self::Target {
        self.resource.as_ref().expect("Resource already taken")
    }
}

impl<R, D> DerefMut for UniqueResource<R, D>
where
    D: FnOnce(R),
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.resource.as_mut().expect("Resource already taken")
    }
}

impl<R, D> Drop for UniqueResource<R, D>
where
    D: FnOnce(R),
{
    fn drop(&mut self) {
        if let (Some(resource), Some(deleter)) = (self.resource.take(), self.deleter.take()) {
            deleter(resource);
        }
    }
}
