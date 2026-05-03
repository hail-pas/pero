use serde::{Deserialize, Deserializer, Serialize, Serializer};
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Debug, Clone, PartialEq)]
pub enum FieldUpdate<T> {
    Unchanged,
    Clear,
    Set(T),
}

impl<T> Default for FieldUpdate<T> {
    fn default() -> Self {
        FieldUpdate::Unchanged
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for FieldUpdate<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|opt| match opt {
            Some(v) => FieldUpdate::Set(v),
            None => FieldUpdate::Clear,
        })
    }
}

impl<T: Serialize> Serialize for FieldUpdate<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FieldUpdate::Set(v) => v.serialize(serializer),
            FieldUpdate::Clear | FieldUpdate::Unchanged => serializer.serialize_none(),
        }
    }
}

impl<T> FieldUpdate<T> {
    pub fn is_unchanged(&self) -> bool {
        matches!(self, FieldUpdate::Unchanged)
    }

    pub fn as_set(&self) -> Option<&T> {
        match self {
            FieldUpdate::Set(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_set(self) -> Option<T> {
        match self {
            FieldUpdate::Set(v) => Some(v),
            _ => None,
        }
    }

    pub fn validate(
        &self,
        field: &'static str,
        errors: &mut ValidationErrors,
        f: impl FnOnce(&T) -> Result<(), ValidationError>,
    ) {
        if let FieldUpdate::Set(v) = self {
            if let Err(err) = f(v) {
                errors.add(field, err);
            }
        }
    }

    pub fn validate_required(
        &self,
        field: &'static str,
        errors: &mut ValidationErrors,
        f: impl FnOnce(&T) -> Result<(), ValidationError>,
    ) {
        match self {
            FieldUpdate::Unchanged => {}
            FieldUpdate::Clear => errors.add(field, ValidationError::new("required")),
            FieldUpdate::Set(v) => {
                if let Err(err) = f(v) {
                    errors.add(field, err);
                }
            }
        }
    }

    pub fn reject_clear(
        &self,
        field: &'static str,
        errors: &mut ValidationErrors,
        f: impl FnOnce(&T) -> Result<(), ValidationError>,
    ) {
        match self {
            FieldUpdate::Unchanged => {}
            FieldUpdate::Clear => errors.add(field, ValidationError::new("required")),
            FieldUpdate::Set(v) => {
                if let Err(err) = f(v) {
                    errors.add(field, err);
                }
            }
        }
    }

    pub fn push_column<'args>(
        &self,
        builder: &mut sqlx::QueryBuilder<'args, sqlx::Postgres>,
        column: &str,
    ) where
        T: 'args + Clone + sqlx::Encode<'args, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
    {
        debug_assert!(
            is_valid_identifier(column),
            "invalid SQL column name: {column}"
        );
        match self {
            FieldUpdate::Unchanged => {}
            FieldUpdate::Clear => {
                builder.push(", ");
                builder.push(column);
                builder.push(" = NULL");
            }
            FieldUpdate::Set(v) => {
                builder.push(", ");
                builder.push(column);
                builder.push(" = ");
                builder.push_bind(v.clone());
            }
        }
    }
}

impl<T: Validate> FieldUpdate<Vec<T>> {
    pub fn validate_nested(&self, field: &'static str, errors: &mut ValidationErrors) {
        if let FieldUpdate::Set(items) = self {
            for (idx, item) in items.iter().enumerate() {
                if let Err(nested) = item.validate() {
                    let mut err = ValidationError::new("nested");
                    err.message = Some(format!("{field}[{idx}] is invalid: {nested}").into());
                    errors.add(field, err);
                }
            }
        }
    }
}

fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.as_bytes().iter().enumerate().all(|(i, b)| {
            if i == 0 {
                b.is_ascii_lowercase() || *b == b'_'
            } else {
                b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_'
            }
        })
}
