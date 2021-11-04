mod errors;
pub mod key_vault;
mod signature;
mod types;
mod x3dh;
mod xeddsa;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
