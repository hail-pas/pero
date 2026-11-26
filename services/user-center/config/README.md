# user-center 配置

配置按 `default.toml`、运行环境文件、`PERO__` 环境变量的顺序覆盖。开发使用 `local.toml`，Docker Compose 通过 `PERO_RUN_MODE=production` 选择 `production.toml`。默认值和字段注释见 [default.toml](default.toml)。

## 配置文件和密钥

| 文件 | 用途 |
| --- | --- |
| [local.toml.example](local.toml.example) | 本地开发示例，复制为 `local.toml` |
| [production.toml.example](../../../deploy/pero/production.toml.example) | 生产示例，复制为 `production.toml` |
| [bootstrap.toml.example](bootstrap.toml.example) | 初始化 Provider 和超级管理员，复制为 `bootstrap.toml` |
| `keys/private.pem`、`keys/public.pem` | 首次初始化导入的 RSA 签名密钥对 |

本地开发将私有文件放在本目录。生产打包默认从仓库根目录的 `local/deploy/pero/config/` 读取私有文件，也可给打包脚本传入 `--config-dir DIR`。打包时采用当前源码的默认配置，保留仍受支持的配置值。已有环境以现网有效配置为准，特别是连接凭据和数据库加密密钥。

新环境需要生成 RSA 密钥时，在私有配置目录执行如下命令。已有密钥时保留现有文件。

```bash
umask 077
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem
openssl pkey -in keys/private.pem -pubout -out keys/public.pem
```

## 生产配置要点

| 字段 | 设置 |
| --- | --- |
| `database.url`、`database.encrypt_key` | 填写 PostgreSQL 连接和独立的数据加密密钥。恢复已有数据库时使用原加密密钥。 |
| `redis.url` | 指向 Pero 专用的 Redis 逻辑库或实例。默认 Compose 使用 host 网络，连接地址按宿主机可达地址填写。 |
| `oidc.issuer`、`sso.base_url` | 使用对外 HTTPS 地址，并保持 `sso.cookie_secure = true`。 |
| `sso.cookie_signing_secret`、`password_reset.signing_key` | 分别生成独立的随机密钥，每个至少 32 字符。可用 `openssl rand -hex 32` 生成。 |
| `server.trusted_proxies`、`server.client_ip_header` | 按实际反代来源设置可信代理地址，且只读取由该代理清洗并写入的客户端 IP 头。 |
| `frontend.static_dir`、`log.dir` | 使用仓库的 Docker Compose 时分别填写 `prd/ui/static` 和 `./logs/prd`。 |
| `bootstrap.toml` 中的 `admin` | 填写初始管理员用户名和符合密码策略的密码。 |

邮件或短信功能需要配置对应渠道，见[应用接入与通知投递](../../../docs/application-portal-and-delivery.md)。私有配置、密钥和配置归档需保存在受限目录，通过 SSH 传输。构建及上线命令见 [Docker 部署指南](../../../deploy/pero/README.md)。
