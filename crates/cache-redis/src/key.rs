use std::{
    fmt::{self, Display},
    marker::PhantomData,
    time::Duration,
};

pub trait CacheValue:
    serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static
{
}

impl<T> CacheValue for T where
    T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static
{
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey<T: CacheValue> {
    raw: String,
    ttl: Option<Duration>,
    spec_name: &'static str,
    _marker: PhantomData<fn() -> T>,
}

impl<T: CacheValue> CacheKey<T> {
    pub(crate) fn new(raw: String, ttl: Option<Duration>, spec_name: &'static str) -> Self {
        Self {
            raw,
            ttl,
            spec_name,
            _marker: PhantomData,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    pub fn spec_name(&self) -> &'static str {
        self.spec_name
    }

    pub fn into_string(self) -> String {
        self.raw
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

impl<T: CacheValue> fmt::Debug for CacheKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheKey")
            .field("raw", &self.raw)
            .field("ttl", &self.ttl)
            .field("spec_name", &self.spec_name)
            .field("value_type", &std::any::type_name::<T>())
            .finish()
    }
}

impl<T: CacheValue> Display for CacheKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

pub trait CacheSpecMeta {
    type Value: CacheValue;

    const NAME: &'static str;
    const PATTERN: &'static str;
    const TTL: Option<Duration>;

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn pattern(&self) -> &'static str {
        Self::PATTERN
    }

    fn ttl(&self) -> Option<Duration> {
        Self::TTL
    }
}

pub trait CacheKeyArg {
    fn to_cache_key_arg(&self) -> Result<String, CacheKeyError>;
}

impl<T> CacheKeyArg for T
where
    T: Display + ?Sized,
{
    fn to_cache_key_arg(&self) -> Result<String, CacheKeyError> {
        let value = self.to_string();

        if value.is_empty() {
            return Err(CacheKeyError::InvalidArgumentValue {
                reason: "cache key argument cannot be empty",
            });
        }

        if value
            .chars()
            .any(|c| matches!(c, '{' | '}' | '\n' | '\r' | '\0'))
        {
            return Err(CacheKeyError::InvalidArgumentValue {
                reason: "cache key argument contains invalid character",
            });
        }

        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheKeyError {
    InvalidPattern {
        key: &'static str,
        pattern: &'static str,
        reason: &'static str,
    },
    MissingArgument {
        key: &'static str,
        argument: String,
    },
    UnexpectedArgument {
        key: &'static str,
        argument: String,
    },
    InvalidArgumentValue {
        reason: &'static str,
    },
}

impl Display for CacheKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern {
                key,
                pattern,
                reason,
            } => write!(
                f,
                "invalid cache key pattern `{key}`: `{pattern}`, reason: {reason}"
            ),
            Self::MissingArgument { key, argument } => {
                write!(f, "missing cache key argument `{argument}` for `{key}`")
            }
            Self::UnexpectedArgument { key, argument } => {
                write!(f, "unexpected cache key argument `{argument}` for `{key}`")
            }
            Self::InvalidArgumentValue { reason } => {
                write!(f, "invalid cache key argument value: {reason}")
            }
        }
    }
}

impl std::error::Error for CacheKeyError {}

impl From<CacheKeyError> for pero_error::AppError {
    fn from(err: CacheKeyError) -> Self {
        pero_error::AppError::internal("cache_key_error", "Invalid cache key").with_source(err)
    }
}

pub fn render_cache_key<T>(
    name: &'static str,
    pattern: &'static str,
    ttl: Option<Duration>,
    args: &[(&'static str, &str)],
) -> Result<CacheKey<T>, CacheKeyError>
where
    T: CacheValue,
{
    let mut out = String::with_capacity(pattern.len() + 32);
    let mut rest = pattern;
    let mut used = vec![false; args.len()];

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);

        let after_open = &rest[open + 1..];

        let Some(close) = after_open.find('}') else {
            return Err(CacheKeyError::InvalidPattern {
                key: name,
                pattern,
                reason: "unclosed placeholder",
            });
        };

        let placeholder = &after_open[..close];

        validate_placeholder(name, pattern, placeholder)?;

        let Some((idx, (_, value))) = args
            .iter()
            .enumerate()
            .find(|(_, (arg_name, _))| *arg_name == placeholder)
        else {
            return Err(CacheKeyError::MissingArgument {
                key: name,
                argument: placeholder.to_string(),
            });
        };

        used[idx] = true;
        out.push_str(value);

        rest = &after_open[close + 1..];
    }

    if rest.contains('}') {
        return Err(CacheKeyError::InvalidPattern {
            key: name,
            pattern,
            reason: "unmatched closing brace",
        });
    }

    out.push_str(rest);

    for (idx, (arg_name, _)) in args.iter().enumerate() {
        if !used[idx] {
            return Err(CacheKeyError::UnexpectedArgument {
                key: name,
                argument: (*arg_name).to_string(),
            });
        }
    }

    Ok(CacheKey::new(out, ttl, name))
}

fn validate_placeholder(
    key: &'static str,
    pattern: &'static str,
    placeholder: &str,
) -> Result<(), CacheKeyError> {
    let mut chars = placeholder.chars();

    let Some(first) = chars.next() else {
        return Err(CacheKeyError::InvalidPattern {
            key,
            pattern,
            reason: "empty placeholder",
        });
    };

    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(CacheKeyError::InvalidPattern {
            key,
            pattern,
            reason: "placeholder must start with alphabetic character or underscore",
        });
    }

    if !chars.all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        return Err(CacheKeyError::InvalidPattern {
            key,
            pattern,
            reason: "placeholder can only contain letters, numbers, or underscore",
        });
    }

    Ok(())
}

/// Generate cache key spec instances.
///
/// Example:
///
/// ```ignore
/// cache_key_specs! {
///     error = crate::error::ValidateError;
///
///     pub user_info: UserInfoKey => UserInfo {
///         pattern: "user_info:{id}",
///         ttl: 300,
///         args: (id: u64),
///     }
///
///     pub user_scene_info: UserSceneInfoKey => UserSceneInfo {
///         pattern: "user_scene_info:{id}:{scene}",
///         ttl: 600,
///         args: (id: u64, scene: &str),
///     }
///
///     pub global_config: GlobalConfigKey => GlobalConfig {
///         pattern: "global_config",
///         ttl: nil,
///         args: (),
///     }
/// }
/// ```
#[macro_export]
macro_rules! cache_key_specs {
    (
        error = $err_ty:ty;

        $(
            $(#[$meta:meta])*
            $vis:vis $instance:ident : $spec_ty:ident => $value_ty:ty {
                pattern: $pattern:literal,
                ttl: $ttl:tt,
                args: ($($arg:ident : $arg_ty:ty),* $(,)?),
            }
        )*
    ) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, Copy, Default)]
            $vis struct $spec_ty;

            #[allow(non_upper_case_globals)]
            $vis const $instance: $spec_ty = $spec_ty;

            impl $crate::CacheSpecMeta for $spec_ty {
                type Value = $value_ty;

                const NAME: &'static str = stringify!($instance);
                const PATTERN: &'static str = $pattern;
                const TTL: Option<::std::time::Duration> =
                    $crate::cache_key_specs!(@ttl $ttl);
            }

            impl $spec_ty {
                pub fn key(
                    &self
                    $(, $arg: $arg_ty)*
                ) -> Result<
                    $crate::CacheKey<$value_ty>,
                    $err_ty
                >
                where
                    $value_ty: $crate::CacheValue,
                    $err_ty: From<$crate::CacheKeyError>,
                {
                    $(
                        let $arg = $crate::CacheKeyArg::to_cache_key_arg(&$arg)
                            .map_err(
                                <$err_ty as From<$crate::CacheKeyError>>::from
                            )?;
                    )*

                    $crate::render_cache_key::<$value_ty>(
                        <$spec_ty as $crate::CacheSpecMeta>::NAME,
                        <$spec_ty as $crate::CacheSpecMeta>::PATTERN,
                        <$spec_ty as $crate::CacheSpecMeta>::TTL,
                        &[
                            $(
                                (stringify!($arg), $arg.as_str()),
                            )*
                        ],
                    )
                    .map_err(
                        <$err_ty as From<$crate::CacheKeyError>>::from
                    )
                }

                pub fn key_with_ttl(
                    &self,
                    ttl: ::std::time::Duration
                    $(, $arg: $arg_ty)*
                ) -> Result<
                    $crate::CacheKey<$value_ty>,
                    $err_ty
                >
                where
                    $value_ty: $crate::CacheValue,
                    $err_ty: From<$crate::CacheKeyError>,
                {
                    self.key($($arg),*).map(|k| k.with_ttl(ttl))
                }
            }
        )*
    };

    (@ttl nil) => {
        None
    };

    (@ttl $secs:literal) => {
        Some(::std::time::Duration::from_secs($secs))
    };
}
