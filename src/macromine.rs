// extern crate syn;

// #[macro_use]
// extern crate quote;

// use std::fs::File;
// use std::io::Read;

// macro_rules! for_each_struct {
//     ($file:expr, $func:ident) => {
//         let mut file = File::open($file).unwrap();
//         let mut contents = String::new();
//         file.read_to_string(&mut contents).unwrap();

//         let syntax = syn::parse_file(&contents).unwrap();
//         for item in &syntax.items {
//             if let syn::Item::Struct(ref struct_def) = *item {
//                 $func(struct_def);
//             }
//         }
//     }
// }