use super::*;

#[test]
fn import_model_editing_updates_recovered_entries() {
    let mut model = ImportModel::default();
    model.add_module("user32.dll", 0x1000, 2).unwrap();
    model
        .add_function(
            "user32.dll",
            0x1000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "MessageBoxW".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "user32.dll",
            0x1008,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "LoadIconW".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model.add_module("ntdll.dll", 0x2000, 1).unwrap();
    model.add_function("ntdll.dll", 0x2000, ImportTarget::Ordinal(1), true, false).unwrap();

    model.set_function_validity(0x1000, false).unwrap();
    let invalid_import = model.imports().into_iter().find(|entry| entry.rva == 0x1000).unwrap();
    assert!(!invalid_import.valid);

    model.rename_module_containing_thunk(0x1008, "win32u.dll").unwrap();
    let renamed_import = model.imports().into_iter().find(|entry| entry.rva == 0x1008).unwrap();
    assert_eq!(renamed_import.module_name, "win32u.dll");
    assert!(matches!(
        model.rename_module_containing_thunk(0x1008, "ntdll.dll"),
        Err(ImportError::ModuleNameCollision(name)) if name == "ntdll.dll"
    ));

    model.remove_function(0x2000).unwrap();
    assert_eq!(model.module_count(), 1);
    assert_eq!(model.function_count(), 2);

    model.remove_module_containing_thunk(0x1008).unwrap();
    assert_eq!(model.module_count(), 0);
    assert_eq!(model.function_count(), 0);
    assert!(matches!(model.set_function_validity(0x1000, true), Err(ImportError::FunctionNotFound(0x1000))));
}

#[test]
fn import_model_cut_thunk_removes_slot_and_splits_tail() {
    let mut model = ImportModel::default();
    model.add_module("kernel32.dll", 0x1000, 4).unwrap();
    for (index, rva) in [0x1000, 0x1008, 0x1010, 0x1018].into_iter().enumerate() {
        model
            .add_function(
                "kernel32.dll",
                rva,
                ImportTarget::Name {
                    hint: 0,
                    ordinal: Some(index as u16),
                    name: format!("Function{index}"),
                },
                true,
                false,
            )
            .unwrap();
    }

    model.cut_thunk(0x1008, 8).unwrap();
    let imports = model.imports();
    let modules = model.modules();

    assert_eq!(imports.len(), 3);
    assert!(!imports.iter().any(|entry| entry.rva == 0x1008));
    assert!(modules.iter().any(|module| {
        module.module_name == "kernel32.dll"
            && module.first_thunk == 0x1000
            && module.nb_thunks == 1
            && module.function_count == 1
    }));
    assert!(modules.iter().any(|module| {
        module.module_name == "?0x1010"
            && module.first_thunk == 0x1010
            && module.nb_thunks == 2
            && module.function_count == 2
    }));
    assert!(imports.iter().any(|entry| {
        entry.module_name == "?0x1010"
            && entry.rva == 0x1010
            && entry.name.as_deref() == Some("Function2")
    }));
    assert!(matches!(model.cut_thunk(0x1008, 8), Err(ImportError::ModuleThunkNotFound(0x1008))));
}
