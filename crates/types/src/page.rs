use pero_validate_core::{Validatable, ValidationResult};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PAGE: u64 = 1;
pub const DEFAULT_PAGE_SIZE: u64 = 20;
pub const MAX_PAGE_SIZE: u64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PageSize(u64);

impl PageSize {
    pub fn new(value: u64) -> Self {
        let normalized = value.clamp(1, MAX_PAGE_SIZE);
        Self(normalized)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self(DEFAULT_PAGE_SIZE)
    }
}

impl Validatable for PageSize {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::treat_as_malformed_input(pero_validate_core::range(
            self.0,
            1,
            MAX_PAGE_SIZE,
            "$",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    #[serde(default = "default_page")]
    pub page: u64,

    #[serde(default)]
    pub page_size: PageSize,
}

impl PageRequest {
    pub fn new(page: u64, page_size: u64) -> Self {
        Self {
            page: page.max(1),
            page_size: PageSize::new(page_size),
        }
    }

    pub fn offset(self) -> u64 {
        self.page.saturating_sub(1) * self.page_size.get()
    }

    pub fn limit(self) -> u64 {
        self.page_size.get()
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            page: DEFAULT_PAGE,
            page_size: PageSize::default(),
        }
    }
}

impl Validatable for PageRequest {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::treat_as_malformed_input((|| {
            pero_validate_core::min(self.page, 1, "$.page")?;
            pero_validate_core::range(self.page_size.get(), 1, MAX_PAGE_SIZE, "$.page_size")?;
            Ok(())
        })())
    }
}

fn default_page() -> u64 {
    DEFAULT_PAGE
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageResult<T> {
    pub items: Vec<T>,
    pub page: u64,
    pub page_size: u64,
    pub total: u64,
}

impl<T> PageResult<T> {
    pub fn new(items: Vec<T>, request: PageRequest, total: u64) -> Self {
        Self {
            items,
            page: request.page,
            page_size: request.page_size.get(),
            total,
        }
    }

    pub fn total_pages(&self) -> u64 {
        if self.page_size == 0 {
            return 0;
        }

        self.total.div_ceil(self.page_size)
    }

    pub fn has_next(&self) -> bool {
        self.page < self.total_pages()
    }

    pub fn has_previous(&self) -> bool {
        self.page > 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CursorPageRequest {
    #[serde(default)]
    pub cursor: Option<String>,

    #[serde(default)]
    pub page_size: PageSize,
}

impl CursorPageRequest {
    pub fn new(cursor: Option<String>, page_size: u64) -> Self {
        Self {
            cursor,
            page_size: PageSize::new(page_size),
        }
    }

    pub fn limit(&self) -> u64 {
        self.page_size.get()
    }
}

impl Validatable for CursorPageRequest {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::treat_as_malformed_input((|| {
            if let Some(cursor) = &self.cursor {
                pero_validate_core::not_blank(cursor, "$.cursor")?;
            }
            pero_validate_core::range(self.page_size.get(), 1, MAX_PAGE_SIZE, "$.page_size")?;
            Ok(())
        })())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorPageResult<T> {
    pub items: Vec<T>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_cursor: Option<String>,

    pub page_size: u64,
}

impl<T> CursorPageResult<T> {
    pub fn new(
        items: Vec<T>,
        request: CursorPageRequest,
        next_cursor: Option<String>,
        previous_cursor: Option<String>,
    ) -> Self {
        Self {
            items,
            next_cursor,
            previous_cursor,
            page_size: request.page_size.get(),
        }
    }

    pub fn has_next(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn has_previous(&self) -> bool {
        self.previous_cursor.is_some()
    }
}
