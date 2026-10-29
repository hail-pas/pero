use crate::cache_key_specs;

cache_key_specs! {
    error = pero_error::AppError;

    pub rl_login_start_ip: RlLoginStartIpKey => u64 {
        pattern: "rl:login_start:ip:{ip}",
        ttl: 60,
        args: (ip: &str),
    }

    pub rl_login_ip: RlLoginIpKey => u64 {
        pattern: "rl:login:ip:{ip}",
        ttl: 900,
        args: (ip: &str),
    }

    pub rl_login_account: RlLoginAccountKey => u64 {
        pattern: "rl:login:account:{account}",
        ttl: 900,
        args: (account: &str),
    }

    pub rl_admin_members: RlAdminMembersKey => u64 { pattern: "rl:admin:members:{actor}", ttl: 60, args: (actor: &str), }

    pub rl_enrollment_email: RlEnrollmentEmailKey => u64 { pattern: "rl:enrollment:email:{hash}", ttl: 3600, args: (hash: &str), }

    pub rl_register_ip: RlRegisterIpKey => u64 {
        pattern: "rl:register:ip:{ip}",
        ttl: 3600,
        args: (ip: &str),
    }

    pub rl_reset_ip: RlResetIpKey => u64 {
        pattern: "rl:reset:ip:{ip}",
        ttl: 3600,
        args: (ip: &str),
    }

    pub rl_reset: RlResetKey => u64 {
        pattern: "rl:reset:{target}",
        ttl: 3600,
        args: (target: &str),
    }

    pub rl_token: RlTokenKey => u64 {
        pattern: "rl:token:{client_id}",
        ttl: 60,
        args: (client_id: &str),
    }

    pub rl_verify_send: RlVerifySendKey => u64 {
        pattern: "rl:verify_send:{user_id}:{change_type}",
        ttl: 300,
        args: (user_id: &str, change_type: &str),
    }

    pub rl_verify_attempt: RlVerifyAttemptKey => u64 {
        pattern: "rl:verify_attempt:{user_id}:{nonce}",
        ttl: 900,
        args: (user_id: &str, nonce: &str),
    }

    pub rl_reset_submit: RlResetSubmitKey => u64 {
        pattern: "rl:reset_submit:{user_id}",
        ttl: 900,
        args: (user_id: &str),
    }

    pub rl_change_password: RlChangePasswordKey => u64 {
        pattern: "rl:change_password:{user_id}",
        ttl: 900,
        args: (user_id: &str),
    }

    pub login_fail: LoginFailKey => u32 {
        pattern: "lockout:{user_id}",
        ttl: 1800,
        args: (user_id: &str),
    }
}
