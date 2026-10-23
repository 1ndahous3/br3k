#[derive(Clone, Debug)]
pub struct Location {
    pub path: String,
    pub line: usize,
}

#[derive(Clone, Debug)]
pub struct Parameter {
    pub name: String,
    pub ty: String,
    pub optional: bool,
    pub keyword: bool,
    pub positional_only: bool,
    pub doc: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodKind { Method, ClassMethod, StaticMethod, Property, Setter, Constructor, Function }

#[derive(Clone, Debug)]
pub struct Method {
    pub name: String,
    pub kind: MethodKind,
    pub parameters: Vec<Parameter>,
    pub returns: String,
    pub doc: String,
    pub location: Location,
}

#[derive(Clone, Debug)]
pub struct Class {
    pub module: String,
    pub name: String,
    pub doc: String,
    pub methods: Vec<Method>,
    pub variants: Vec<(String, String)>,
    pub location: Location,
}

#[derive(Default)]
pub struct Api {
    pub modules: std::collections::BTreeMap<String, String>,
    pub classes: Vec<Class>,
    pub functions: Vec<(String, Method)>,
    pub constants: Vec<(String, String, String)>,
    pub aliases: Vec<(String, String, String)>,
}
