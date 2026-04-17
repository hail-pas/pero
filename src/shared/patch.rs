use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq)]
pub enum Patch<T> {
    Absent,
    Null,
    Set(T),
}

impl<T> Default for Patch<T> {
    fn default() -> Self {
        Patch::Absent
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|opt| match opt {
            Some(v) => Patch::Set(v),
            None => Patch::Null,
        })
    }
}

impl<T: Serialize> Serialize for Patch<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Patch::Set(v) => v.serialize(serializer),
            Patch::Null | Patch::Absent => serializer.serialize_none(),
        }
    }
}

impl<T> Patch<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Patch::Absent)
    }

    pub fn validate_set(
        &self,
        f: impl FnOnce(&T) -> Result<(), validator::ValidationError>,
    ) -> Result<(), validator::ValidationError> {
        match self {
            Patch::Set(v) => f(v),
            _ => Ok(()),
        }
    }

    pub fn push_column<'args>(
        &self,
        builder: &mut sqlx::QueryBuilder<'args, sqlx::Postgres>,
        column: &str,
    ) where
        T: 'args + Clone + sqlx::Encode<'args, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
    {
        match self {
            Patch::Absent => {}
            Patch::Null => {
                builder.push(", ");
                builder.push(column);
                builder.push(" = NULL");
            }
            Patch::Set(v) => {
                builder.push(", ");
                builder.push(column);
                builder.push(" = ");
                builder.push_bind(v.clone());
            }
        }
    }
}

pub fn validate_patch<T>(
    patch: &Patch<T>,
    field: &'static str,
    f: impl FnOnce(&T) -> Result<(), validator::ValidationError>,
    errors: &mut validator::ValidationErrors,
) {
    if let Err(e) = patch.validate_set(f) {
        errors.add(field, e);
    }
}

pub fn push_optional_column<'args, T>(
    builder: &mut sqlx::QueryBuilder<'args, sqlx::Postgres>,
    column: &str,
    opt: &Option<T>,
) where
    T: 'args + Clone + sqlx::Encode<'args, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    if let Some(v) = opt {
        builder.push(", ");
        builder.push(column);
        builder.push(" = ");
        builder.push_bind(v.clone());
    }
}
