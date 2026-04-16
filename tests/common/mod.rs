#![allow(unused_imports, dead_code)]

mod app;
mod cleanup;
mod client;
mod fixtures;
mod isolation;

pub use app::{TestApp, build_app, build_router};
pub use client::send_request;
pub use fixtures::{
    AppFixture, ClientFixture, PolicyFixture, UserFixture,
    login_user_inner, register_user_inner,
};
pub use isolation::{unique_email, unique_name};
