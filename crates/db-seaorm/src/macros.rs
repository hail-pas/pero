#[macro_export]
macro_rules! paginate {
    ($query:expr, $db:expr, $page:expr, $page_size:expr) => {{
        let total = $query.clone().count($db).await?;
        let total_pages = total.div_ceil($page_size);
        let offset = ($page).saturating_sub(1) * $page_size;
        let items = $query.offset(offset).limit($page_size).all($db).await?;
        Ok((items, total_pages))
    }};
}

#[macro_export]
macro_rules! enum_display_cmp {
    ($enum:path { $($variant:ident => $val:literal),+ $(,)? }) => {
        impl std::fmt::Display for $enum {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$variant => write!(f, $val)),+
                }
            }
        }
        impl PartialEq<&str> for $enum {
            fn eq(&self, other: &&str) -> bool {
                match self {
                    $(Self::$variant => $val == *other),+
                }
            }
        }
    };
}

#[macro_export]
macro_rules! enum_from_str {
    ($enum:path { $($val:literal => $variant:ident),+ $(,)? }) => {
        impl $enum {
            pub fn try_from_str(s: &str) -> Result<Self, &'static str> {
                match s {
                    $($val => Ok(Self::$variant),)+
                    _ => Err(concat!("invalid value: ", stringify!($enum))),
                }
            }
        }
    };
}
