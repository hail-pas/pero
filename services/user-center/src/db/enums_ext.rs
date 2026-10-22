pero_db_seaorm::enum_display_cmp!(crate::db::enums::AppType { Web => "web", Spa => "spa", Mobile => "mobile", Service => "service" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::CommonStatus { Active => "active", Disabled => "disabled" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::IdentityKind { Password => "password", Oauth => "oauth" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::IdentityProviderKind { Wechat => "wechat", Local => "local", Oauth2 => "oauth2", Oidc => "oidc" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::KeyAlgorithm { Rs256 => "RS256", Rs384 => "RS384", Rs512 => "RS512", Es256 => "ES256", Es384 => "ES384", Es512 => "ES512" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::KeyUse { Sig => "sig", Enc => "enc" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::OauthClientType { Confidential => "confidential", Public => "public" });
pero_db_seaorm::enum_display_cmp!(crate::db::enums::UserStatus { Active => "active", Disabled => "disabled", Locked => "locked" });

pero_db_seaorm::enum_from_str!(crate::db::enums::AppType { "web" => Web, "spa" => Spa, "mobile" => Mobile, "service" => Service });
pero_db_seaorm::enum_from_str!(crate::db::enums::CommonStatus { "active" => Active, "disabled" => Disabled });
pero_db_seaorm::enum_from_str!(crate::db::enums::UserStatus { "active" => Active, "disabled" => Disabled, "locked" => Locked });
pero_db_seaorm::enum_from_str!(crate::db::enums::IdentityProviderKind { "wechat" => Wechat, "local" => Local, "oauth2" => Oauth2, "oidc" => Oidc });
pero_db_seaorm::enum_from_str!(crate::db::enums::KeyAlgorithm { "RS256" => Rs256, "RS384" => Rs384, "RS512" => Rs512, "ES256" => Es256, "ES384" => Es384, "ES512" => Es512 });
pero_db_seaorm::enum_from_str!(crate::db::enums::KeyUse { "sig" => Sig, "enc" => Enc });
pero_db_seaorm::enum_from_str!(crate::db::enums::OauthClientType { "confidential" => Confidential, "public" => Public });

impl crate::db::enums::IdentityProviderKind {
    pub fn is_social(&self) -> bool {
        matches!(self, Self::Oauth2 | Self::Oidc | Self::Wechat)
    }
}
