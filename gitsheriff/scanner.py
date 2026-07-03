"""
GitSheriff - Sensitive data scanner module.

Scans extracted/recovered files for sensitive information using
regex-based pattern matching. Detects secrets, passwords, API keys,
private keys, tokens, connection strings, environment variables,
and other credentials.
"""

import os
import re
import json
import time
from collections import defaultdict

from .utils import (
    Colors, print_info, print_success, print_warning, print_error,
    print_section, ProgressBar, safe_makedirs,
)


# ---------------------------------------------------------------------------
# Pattern definitions: (name, severity, regex_pattern, description)
# ---------------------------------------------------------------------------
PATTERNS = [
    # =====================================================================
    # CRITICAL - Private keys & certificates
    # =====================================================================
    (
        "Private Key (RSA)",
        "CRITICAL",
        re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "RSA private key (PEM format)",
    ),
    (
        "Private Key (EC)",
        "CRITICAL",
        re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        "Elliptic curve private key (PEM format)",
    ),
    (
        "Private Key (Generic)",
        "CRITICAL",
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
        "Generic private key (PKCS#8 PEM format)",
    ),
    (
        "PGP Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "PGP/GPG private key block",
    ),
    (
        "DSA Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        "DSA private key (PEM format)",
    ),
    (
        "OpenSSH Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "OpenSSH private key",
    ),
    (
        "SSH Private Key (Ed25519)",
        "CRITICAL",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----.*?openssh-key-v1", re.DOTALL),
        "Ed25519 SSH private key",
    ),
    (
        "TLS/SSL Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]{100,}-----END (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        "TLS/SSL private key block",
    ),

    # =====================================================================
    # CRITICAL - .env file secrets & variable patterns
    # =====================================================================
    (
        ".env SECRET_KEY / Django",
        "CRITICAL",
        re.compile(r"(?:SECRET_KEY|DJANGO_SECRET_KEY|SECRET_KEY_BASE)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Django/framework SECRET_KEY exposed",
    ),
    (
        ".env DATABASE_PASSWORD",
        "CRITICAL",
        re.compile(r"(?:DATABASE_PASSWORD|DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Database password in environment/config",
    ),
    (
        ".env API_SECRET",
        "CRITICAL",
        re.compile(r"(?:API_SECRET|API_SECRET_KEY|APP_SECRET|APPLICATION_SECRET)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "API/application secret key exposed",
    ),
    (
        ".env ENCRYPTION_KEY",
        "CRITICAL",
        re.compile(r"(?:ENCRYPTION_KEY|ENCRYPT_KEY|MASTER_KEY|MASTER_ENCRYPTION_KEY|DATA_ENCRYPTION_KEY|DEK|KEK)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Encryption/master key exposed",
    ),
    (
        ".env PRIVATE_KEY",
        "CRITICAL",
        re.compile(r"(?:PRIVATE_KEY|SIGNING_KEY|SIGN_KEY)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Private/signing key exposed",
    ),
    (
        ".env JWT_SECRET",
        "CRITICAL",
        re.compile(r"(?:JWT_SECRET|JWT_SECRET_KEY|TOKEN_SECRET|AUTH_SECRET)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "JWT/auth secret exposed",
    ),

    # =====================================================================
    # HIGH - Cloud provider & SaaS tokens
    # =====================================================================
    (
        "AWS Access Key",
        "HIGH",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS IAM access key ID",
    ),
    (
        "AWS Secret Key",
        "HIGH",
        re.compile(r"(?:aws_secret_access_key|aws_secret_key|secret_access_key|AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE),
        "AWS IAM secret access key",
    ),
    (
        "AWS Session Token",
        "HIGH",
        re.compile(r"(?:aws_session_token|AWS_SESSION_TOKEN|SessionToken)[\s:=]+['\"]?([A-Za-z0-9/+=]{100,})['\"]?", re.IGNORECASE),
        "AWS temporary session token",
    ),
    (
        "AWS MWS Key",
        "HIGH",
        re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "Amazon MWS authentication token",
    ),
    (
        "GitHub Token",
        "HIGH",
        re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}"),
        "GitHub personal/oauth/app/refresh token",
    ),
    (
        "GitLab Token",
        "HIGH",
        re.compile(r"glpat-[A-Za-z0-9\-_]{20,}|glptt-[A-Za-z0-9\-_]{20,}|gli-[A-Za-z0-9\-_]{20,}"),
        "GitLab personal/project/pipeline token",
    ),
    (
        "Slack Token",
        "HIGH",
        re.compile(r"xox[bpsa]-[0-9]{10,}-[0-9a-zA-Z\-]+"),
        "Slack bot/user/app token",
    ),
    (
        "Slack Webhook",
        "HIGH",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
        "Slack incoming webhook URL",
    ),
    (
        "Stripe Key",
        "HIGH",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}"),
        "Stripe API live key",
    ),
    (
        "Google API Key",
        "HIGH",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Google API key",
    ),
    (
        "Google OAuth Secret",
        "HIGH",
        re.compile(r"GOCSPX-[A-Za-z0-9\-_]{28,}"),
        "Google OAuth client secret",
    ),
    (
        "Heroku API Key",
        "HIGH",
        re.compile(r"(?:heroku_api_key|HEROKU_API_KEY)[\s:=]+['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", re.IGNORECASE),
        "Heroku API key",
    ),
    (
        "Twilio API Key",
        "HIGH",
        re.compile(r"SK[0-9a-fA-F]{32}"),
        "Twilio API key",
    ),
    (
        "SendGrid API Key",
        "HIGH",
        re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
        "SendGrid API key",
    ),
    (
        "Mailgun API Key",
        "HIGH",
        re.compile(r"key-[0-9a-zA-Z]{32}"),
        "Mailgun API key",
    ),
    (
        "Shopify Token",
        "HIGH",
        re.compile(r"shpat_[a-fA-F0-9]{32}"),
        "Shopify private app access token",
    ),
    (
        "Confluent API Key",
        "HIGH",
        re.compile(r"(?:CONFLUENT_API_KEY|confluent_api_key)[\s:=]+['\"]?([A-Za-z0-9]{16,})['\"]?", re.IGNORECASE),
        "Confluent/Kafka API key",
    ),
    (
        "Datadog API Key",
        "HIGH",
        re.compile(r"(?:DD_API_KEY|DATADOG_API_KEY|dd_api_key)[\s:=]+['\"]?([a-f0-9]{32})['\"]?", re.IGNORECASE),
        "Datadog API key",
    ),
    (
        "New Relic Key",
        "HIGH",
        re.compile(r"NRAK-[A-Z0-9]{27}"),
        "New Relic API key",
    ),
    (
        "PagerDuty Token",
        "HIGH",
        re.compile(r"(?:pd_api_key|PAGERDUTY_TOKEN|PAGERDUTY_API_KEY)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.IGNORECASE),
        "PagerDuty API key",
    ),
    (
        "Twilio Account SID",
        "HIGH",
        re.compile(r"AC[a-f0-9]{32}"),
        "Twilio Account SID (may indicate associated secret)",
    ),
    (
        "Sentry DSN with Auth",
        "HIGH",
        re.compile(r"https://[a-f0-9]{32}@[a-z0-9.\-]+/[0-9]+"),
        "Sentry DSN with embedded auth token",
    ),

    # =====================================================================
    # HIGH - Database & service passwords in .env style
    # =====================================================================
    (
        ".env REDIS_PASSWORD",
        "HIGH",
        re.compile(r"(?:REDIS_PASSWORD|REDIS_AUTH|REDIS_URL_AUTH|REDIS_PASS)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Redis password exposed",
    ),
    (
        ".env SMTP_PASSWORD",
        "HIGH",
        re.compile(r"(?:SMTP_PASSWORD|SMTP_PASS|MAIL_PASSWORD|EMAIL_PASSWORD|EMAIL_SMTP_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "SMTP/email password exposed",
    ),
    (
        ".env FTP_PASSWORD",
        "HIGH",
        re.compile(r"(?:FTP_PASSWORD|FTP_PASS|FTP_SECRET)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "FTP password exposed",
    ),
    (
        ".env SSH_PASSWORD",
        "HIGH",
        re.compile(r"(?:SSH_PASSWORD|SSH_PASS|SSH_SECRET)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "SSH password exposed",
    ),
    (
        ".env STORAGE_PASSWORD",
        "HIGH",
        re.compile(r"(?:STORAGE_PASSWORD|S3_PASSWORD|MINIO_SECRET_KEY|MINIO_ROOT_PASSWORD|BUCKETEER_AWS_SECRET_ACCESS_KEY)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Cloud storage password exposed",
    ),
    (
        ".env ELASTICSEARCH_PASSWORD",
        "HIGH",
        re.compile(r"(?:ELASTIC_PASSWORD|ELASTICSEARCH_PASSWORD|ELASTICSEARCH_PASS)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Elasticsearch password exposed",
    ),
    (
        ".env MONGODB_PASSWORD",
        "HIGH",
        re.compile(r"(?:MONGODB_PASSWORD|MONGO_PASS|MONGO_INITDB_ROOT_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "MongoDB password exposed",
    ),
    (
        ".env MYSQL_ROOT_PASSWORD",
        "HIGH",
        re.compile(r"(?:MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MYSQL_PASS)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "MySQL password exposed",
    ),
    (
        ".env POSTGRES_PASSWORD",
        "HIGH",
        re.compile(r"(?:POSTGRES_PASSWORD|POSTGRES_PASS|PG_PASSWORD|PG_PASS|POSTGRESQL_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "PostgreSQL password exposed",
    ),

    # =====================================================================
    # HIGH - Cloud-specific credentials in .env format
    # =====================================================================
    (
        ".env AZURE_CLIENT_SECRET",
        "HIGH",
        re.compile(r"(?:AZURE_CLIENT_SECRET|AZURE_SECRET|AZURE_APP_SECRET|ARM_CLIENT_SECRET)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Azure service principal secret",
    ),
    (
        ".env GCP_SERVICE_ACCOUNT_KEY",
        "HIGH",
        re.compile(r"(?:GOOGLE_APPLICATION_CREDENTIALS|GCP_SA_KEY|GCLOUD_SERVICE_KEY)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "GCP service account key path/reference",
    ),
    (
        ".env DIGITALOCEAN_TOKEN",
        "HIGH",
        re.compile(r"(?:DIGITALOCEAN_ACCESS_TOKEN|DO_API_TOKEN|DIGITALOCEAN_TOKEN)[\s:=]+['\"]?([^\s'\"]{64})['\"]?", re.IGNORECASE),
        "DigitalOcean API token",
    ),
    (
        ".env CLOUDFLARE_TOKEN",
        "HIGH",
        re.compile(r"(?:CLOUDFLARE_API_KEY|CF_API_KEY|CLOUDFLARE_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Cloudflare API token",
    ),
    (
        ".env FASTLY_TOKEN",
        "HIGH",
        re.compile(r"(?:FASTLY_API_KEY|FASTLY_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Fastly API token",
    ),
    (
        ".env NGINX_PASSWORD",
        "HIGH",
        re.compile(r"(?:NGINX_PASSWORD|NGINX_PASS|TRAEFIK_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Nginx/Traefik admin password",
    ),

    # =====================================================================
    # HIGH - Third-party service tokens
    # =====================================================================
    (
        "npm Token",
        "HIGH",
        re.compile(r"npm_[A-Za-z0-9]{36}"),
        "npm access token",
    ),
    (
        "PyPI Token",
        "HIGH",
        re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
        "PyPI API token",
    ),
    (
        "RubyGems Token",
        "HIGH",
        re.compile(r"rubygems_[a-f0-9]{48}"),
        "RubyGems API key",
    ),
    (
        "NuGet API Key",
        "HIGH",
        re.compile(r"oy2[a-z0-9]{43}"),
        "NuGet API key",
    ),
    (
        "Maven Password",
        "HIGH",
        re.compile(r"(?:MAVEN_PASSWORD|MAVEN_PASS|SONATYPE_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Maven/Sonatype repository password",
    ),
    (
        "Docker Hub Token",
        "HIGH",
        re.compile(r"(?:DOCKER_PASSWORD|DOCKER_TOKEN|DOCKERHUB_TOKEN|DOCKERHUB_PASSWORD)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Docker Hub password/token",
    ),
    (
        "Netskope Token",
        "HIGH",
        re.compile(r"(?:netskope_api_key|NETSKOPE_API_KEY)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Netskope API token",
    ),
    (
        "Vault Token",
        "HIGH",
        re.compile(r"hvs\.[A-Za-z0-9]{24,}"),
        "HashiCorp Vault service token",
    ),
    (
        "Vault Batch Token",
        "HIGH",
        re.compile(r"hvb\.[A-Za-z0-9]{24,}"),
        "HashiCorp Vault batch token",
    ),
    (
        "Vault Root Token",
        "HIGH",
        re.compile(r"hvr\.[A-Za-z0-9]{24,}"),
        "HashiCorp Vault root token",
    ),

    # =====================================================================
    # MEDIUM - API keys, tokens, auth patterns
    # =====================================================================
    (
        "JWT Token",
        "MEDIUM",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        "JSON Web Token (JWT)",
    ),
    (
        "Generic API Key",
        "MEDIUM",
        re.compile(r"(?:api_key|apikey|api-key|API_KEY|APIKEY|API_SECRET)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.IGNORECASE),
        "Generic API key",
    ),
    (
        "Bearer Token",
        "MEDIUM",
        re.compile(r"(?:bearer|token|auth)[\s:=]+['\"]?Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE),
        "Bearer authentication token",
    ),
    (
        "Basic Auth Header",
        "MEDIUM",
        re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"),
        "Basic authentication header (base64 encoded)",
    ),
    (
        "Authorization Header",
        "MEDIUM",
        re.compile(r"Authorization:\s*(?:Bearer|Token|Basic|Digest)\s+[^\s]{10,}", re.IGNORECASE),
        "Authorization header with credential",
    ),
    (
        "Access Token",
        "MEDIUM",
        re.compile(r"(?:access_token|ACCESS_TOKEN|auth_token|AUTH_TOKEN)[\s:=]+['\"]?([A-Za-z0-9\-_.]{20,})['\"]?", re.IGNORECASE),
        "Access token exposed",
    ),
    (
        "Refresh Token",
        "MEDIUM",
        re.compile(r"(?:refresh_token|REFRESH_TOKEN)[\s:=]+['\"]?([A-Za-z0-9\-_.]{20,})['\"]?", re.IGNORECASE),
        "Refresh token exposed",
    ),
    (
        "OAuth Client Secret",
        "MEDIUM",
        re.compile(r"(?:client_secret|CLIENT_SECRET|oauth_secret|OAUTH_SECRET)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "OAuth client secret",
    ),

    # =====================================================================
    # MEDIUM - .env variable names suggesting passwords
    # =====================================================================
    (
        ".env PASSWORD variable",
        "MEDIUM",
        re.compile(r"(?:^|[\s\"'])([A-Z_]*(?:PASSWORD|PASSWD|PASS_PHRASE|PASSPHRASE)[A-Z_0-9]*)\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?", re.MULTILINE | re.IGNORECASE),
        "Environment variable with password-like name",
    ),
    (
        ".env SECRET variable",
        "MEDIUM",
        re.compile(r"(?:^|[\s\"'])([A-Z_]*SECRET[A-Z_0-9]*)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.MULTILINE | re.IGNORECASE),
        "Environment variable with secret-like name",
    ),
    (
        ".env TOKEN variable",
        "MEDIUM",
        re.compile(r"(?:^|[\s\"'])([A-Z_]*TOKEN[A-Z_0-9]*)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?", re.MULTILINE | re.IGNORECASE),
        "Environment variable with token-like name",
    ),
    (
        ".env CREDENTIAL variable",
        "MEDIUM",
        re.compile(r"(?:^|[\s\"'])([A-Z_]*CREDENTIAL[A-Z_0-9]*)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.MULTILINE | re.IGNORECASE),
        "Environment variable with credential-like name",
    ),
    (
        ".env AUTH variable",
        "MEDIUM",
        re.compile(r"(?:^|[\s\"'])([A-Z_]*AUTH[A-Z_0-9]*)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.MULTILINE | re.IGNORECASE),
        "Environment variable with auth-like name",
    ),
    (
        ".env KEY variable",
        "MEDIUM",
        re.compile(r"(?:^|[\s\"'])([A-Z_]*KEY[A-Z_0-9]*)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.MULTILINE | re.IGNORECASE),
        "Environment variable with key-like name",
    ),

    # =====================================================================
    # MEDIUM - Passwords in code
    # =====================================================================
    (
        "Password in Code",
        "MEDIUM",
        re.compile(r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
        "Password hardcoded in source code",
    ),
    (
        "Password Variable Assignment",
        "MEDIUM",
        re.compile(r"(?:password|passwd|pwd)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
        "Password assigned to a variable",
    ),
    (
        "Secret Variable Assignment",
        "MEDIUM",
        re.compile(r"(?:secret|secret_key|api_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE),
        "Secret value hardcoded in source code",
    ),
    (
        "Token Variable Assignment",
        "MEDIUM",
        re.compile(r"(?:token|access_token|auth_token)\s*[:=]\s*['\"]([^'\"]{10,})['\"]", re.IGNORECASE),
        "Token value hardcoded in source code",
    ),
    (
        "Credentials in Code",
        "MEDIUM",
        re.compile(r"(?:credentials?|creds)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE),
        "Credentials hardcoded in source code",
    ),

    # =====================================================================
    # MEDIUM - Connection strings & URLs with credentials
    # =====================================================================
    (
        "Database URL with Credentials",
        "MEDIUM",
        re.compile(r"(?:mysql|postgres|postgresql|mongodb|redis|sqlite|amqp|mssql|oracle)://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
        "Database connection string with credentials",
    ),
    (
        "MySQL URL",
        "MEDIUM",
        re.compile(r"mysql://[^:\s]+:[^@\s]+@[^/\s]+/\S+"),
        "MySQL connection URL with credentials",
    ),
    (
        "PostgreSQL URL",
        "MEDIUM",
        re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/\S+"),
        "PostgreSQL connection URL with credentials",
    ),
    (
        "MongoDB URL",
        "MEDIUM",
        re.compile(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+/\S+"),
        "MongoDB connection URL with credentials",
    ),
    (
        "Redis URL",
        "MEDIUM",
        re.compile(r"redis://[^:\s]*:[^@\s]+@[^\s]+"),
        "Redis connection URL with credentials",
    ),
    (
        "FTP URL",
        "MEDIUM",
        re.compile(r"ftp://[^:\s]+:[^@\s]+@[^\s]+"),
        "FTP URL with credentials",
    ),
    (
        "SSH Connection String",
        "MEDIUM",
        re.compile(r"ssh://[^:\s]+:[^@\s]+@[^\s]+"),
        "SSH connection string with password",
    ),
    (
        "SMTP Credentials",
        "MEDIUM",
        re.compile(r"(?:smtp|mail)[\s:=]+[^\s]*://[^:\s]+:[^@\s]+@[^\s]+"),
        "SMTP connection with credentials",
    ),
    (
        "AMQP URL",
        "MEDIUM",
        re.compile(r"amqps?://[^:\s]+:[^@\s]+@[^\s]+"),
        "AMQP/RabbitMQ connection URL with credentials",
    ),
    (
        "Elasticsearch URL",
        "MEDIUM",
        re.compile(r"https?://[^:\s]+:[^@\s]+@[^\s]*(?:elasticsearch|elastic|opensearch)"),
        "Elasticsearch/OpenSearch URL with credentials",
    ),
    (
        "Kafka Connection",
        "MEDIUM",
        re.compile(r"(?:KAFKA_PASSWORD|KAFKA_SASL_PASSWORD|KAFKA_SECRET)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Kafka connection credential",
    ),

    # =====================================================================
    # MEDIUM - Cloud provider connection strings
    # =====================================================================
    (
        "Azure Storage Account Key",
        "MEDIUM",
        re.compile(r"AccountKey=[A-Za-z0-9+/=]{44,}"),
        "Azure Storage account key",
    ),
    (
        "Azure Connection String",
        "MEDIUM",
        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+"),
        "Azure Storage connection string",
    ),
    (
        "Azure AD Client Secret",
        "MEDIUM",
        re.compile(r"(?:AZURE_CLIENT_SECRET|AAD_CLIENT_SECRET)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Azure AD client secret",
    ),
    (
        "GCP Service Account",
        "MEDIUM",
        re.compile(r'"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]*"'),
        "GCP service account private key (JSON)",
    ),
    (
        "Heroku Database URL",
        "MEDIUM",
        re.compile(r"HEROKU_DATABASE_URL[\s:=]+['\"]?(postgres://[^\s'\"]+)['\"]?", re.IGNORECASE),
        "Heroku Postgres database URL",
    ),

    # =====================================================================
    # MEDIUM - Service-specific secrets
    # =====================================================================
    (
        "Twitch Token",
        "MEDIUM",
        re.compile(r"oauth:[a-z0-9]{30}"),
        "Twitch OAuth token",
    ),
    (
        "Discord Token",
        "MEDIUM",
        re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"),
        "Discord bot token",
    ),
    (
        "Discord Webhook",
        "MEDIUM",
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
        "Discord webhook URL",
    ),
    (
        "Telegram Bot Token",
        "MEDIUM",
        re.compile(r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),
        "Telegram bot token",
    ),
    (
        "Twilio Auth Token",
        "MEDIUM",
        re.compile(r"(?:TWILIO_AUTH_TOKEN|twilio_auth_token)[\s:=]+['\"]?([a-f0-9]{32})['\"]?", re.IGNORECASE),
        "Twilio auth token",
    ),
    (
        "Nexmo/Vonage Key",
        "MEDIUM",
        re.compile(r"(?:NEXMO_API_KEY|VONAGE_API_KEY)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Nexmo/Vonage API key",
    ),
    (
        "Alibaba Access Key",
        "MEDIUM",
        re.compile(r"(?:ALIBABA_ACCESS_KEY|ALI_ACCESS_KEY|OSS_ACCESS_KEY)[\s:=]+['\"]?([A-Za-z0-9]{20,})['\"]?", re.IGNORECASE),
        "Alibaba Cloud access key",
    ),
    (
        "Tencent Secret ID",
        "MEDIUM",
        re.compile(r"(?:TENCENT_SECRET_ID|TENCENTCLOUD_SECRET_ID)[\s:=]+['\"]?([A-Za-z0-9]{20,})['\"]?", re.IGNORECASE),
        "Tencent Cloud secret ID",
    ),
    (
        "Vercel Token",
        "MEDIUM",
        re.compile(r"(?:VERCEL_TOKEN|vercel_token)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.IGNORECASE),
        "Vercel deployment token",
    ),
    (
        "Netlify Token",
        "MEDIUM",
        re.compile(r"(?:NETLIFY_AUTH_TOKEN|netlify_auth_token)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.IGNORECASE),
        "Netlify auth token",
    ),
    (
        "Supabase Key",
        "MEDIUM",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+.*(?:supabase|SUPABASE)"),
        "Supabase API/service key",
    ),
    (
        "Algolia API Key",
        "MEDIUM",
        re.compile(r"(?:ALGOLIA_API_KEY|ALGOLIA_SEARCH_KEY)[\s:=]+['\"]?([a-f0-9]{32})['\"]?", re.IGNORECASE),
        "Algolia API key",
    ),
    (
        "RapidAPI Key",
        "MEDIUM",
        re.compile(r"(?:RAPIDAPI_KEY|rapidapi_key)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "RapidAPI key",
    ),
    (
        "Cloudinary URL",
        "MEDIUM",
        re.compile(r"cloudinary://[^\s]+:[^\s]+@[^\s]+"),
        "Cloudinary URL with credentials",
    ),
    (
        "Twilio Connection String",
        "MEDIUM",
        re.compile(r"(?:TWILIO_ACCOUNT_SID|TWILIO_AUTH_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Twilio connection credential",
    ),

    # =====================================================================
    # MEDIUM - Docker & CI/CD secrets
    # =====================================================================
    (
        "Docker Password",
        "MEDIUM",
        re.compile(r"(?:DOCKER_PASSWORD|DOCKER_PASS|DOCKER_TOKEN|DOCKERHUB_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Docker registry password",
    ),
    (
        "CI/CD Token",
        "MEDIUM",
        re.compile(r"(?:CI_TOKEN|CI_JOB_TOKEN|BUILD_TOKEN|PIPELINE_TOKEN|DEPLOY_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "CI/CD pipeline token",
    ),
    (
        "Jenkins Token",
        "MEDIUM",
        re.compile(r"(?:JENKINS_TOKEN|JENKINS_API_TOKEN|JENKINS_PASSWORD)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Jenkins API token/password",
    ),
    (
        "CircleCI Token",
        "MEDIUM",
        re.compile(r"(?:CIRCLE_TOKEN|CIRCLECI_TOKEN|CIRCLE_API_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "CircleCI API token",
    ),
    (
        "Travis CI Token",
        "MEDIUM",
        re.compile(r"(?:TRAVIS_TOKEN|TRAVIS_API_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Travis CI token",
    ),
    (
        "GitHub Actions Secret",
        "MEDIUM",
        re.compile(r"(?:GITHUB_TOKEN|GH_TOKEN)[\s:=]+['\"]?((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})['\"]?", re.IGNORECASE),
        "GitHub Actions secret token",
    ),

    # =====================================================================
    # MEDIUM - Kubernetes & container orchestration
    # =====================================================================
    (
        "Kubernetes Secret",
        "MEDIUM",
        re.compile(r"(?:KUBE_TOKEN|KUBERNETES_TOKEN|K8S_TOKEN)[\s:=]+['\"]?([A-Za-z0-9\-_.]{20,})['\"]?", re.IGNORECASE),
        "Kubernetes API token",
    ),
    (
        "Kubeconfig with Password",
        "MEDIUM",
        re.compile(r"(?:password|passwd)[\s:]+[^\s]+.*?(?:kubectl|kubernetes|k8s)", re.IGNORECASE),
        "Kubernetes credential in config",
    ),
    (
        "Helm Chart Secret",
        "MEDIUM",
        re.compile(r"(?:HELM_TOKEN|HELM_PASSWORD|CHART_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Helm chart repository secret",
    ),

    # =====================================================================
    # MEDIUM - Infrastructure as Code secrets
    # =====================================================================
    (
        "Ansible Vault Password",
        "MEDIUM",
        re.compile(r"(?:ANSIBLE_VAULT_PASSWORD|VAULT_PASSWORD|ANSIBLE_VAULT_PASS_FILE)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "Ansible Vault password",
    ),
    (
        "Terraform Cloud Token",
        "MEDIUM",
        re.compile(r"(?:TF_TOKEN|TF_CLOUD_TOKEN|TERRAFORM_TOKEN)[\s:=]+['\"]?([A-Za-z0-9\-_.]{20,})['\"]?", re.IGNORECASE),
        "Terraform Cloud token",
    ),
    (
        "Terraform S3 Backend",
        "MEDIUM",
        re.compile(r"(?:AWS_S3_ACCESS_KEY|TF_S3_ACCESS_KEY|S3_ACCESS_KEY)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Terraform S3 backend access key",
    ),
    (
        "Pulumi Access Token",
        "MEDIUM",
        re.compile(r"(?:PULUMI_ACCESS_TOKEN|pulumi_access_token)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Pulumi access token",
    ),
    (
        "Chef Validation Key",
        "MEDIUM",
        re.compile(r"(?:CHEF_VALIDATION_KEY|chef_validation_key)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Chef validation key",
    ),
    (
        "Puppet Hiera Key",
        "MEDIUM",
        re.compile(r"(?:PUPPET_HIERA_KEY|puppet_hiera_key)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Puppet Hiera encrypted key",
    ),

    # =====================================================================
    # MEDIUM - Cryptographic secrets
    # =====================================================================
    (
        "SSH Passphrase",
        "MEDIUM",
        re.compile(r"(?:SSH_PASSPHRASE|SSH_KEY_PASSPHRASE|SSH_KEY_PASSWORD|KEY_PASSPHRASE)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "SSH key passphrase",
    ),
    (
        "PGP Passphrase",
        "MEDIUM",
        re.compile(r"(?:PGP_PASSPHRASE|GPG_PASSPHRASE|PGP_PASSWORD|GPG_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "PGP/GPG key passphrase",
    ),
    (
        "SSL Certificate Password",
        "MEDIUM",
        re.compile(r"(?:SSL_PASSWORD|CERT_PASSWORD|TLS_PASSWORD|KEYSTORE_PASSWORD|TRUSTSTORE_PASSWORD)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        "SSL/keystore password",
    ),

    # =====================================================================
    # MEDIUM - Social media & OAuth
    # =====================================================================
    (
        "Facebook Access Token",
        "MEDIUM",
        re.compile(r"EAAG[0-9A-Za-z]+"),
        "Facebook access token",
    ),
    (
        "Twitter Access Token",
        "MEDIUM",
        re.compile(r"(?:TWITTER_ACCESS_TOKEN|TWITTER_SECRET_KEY)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Twitter/X API token",
    ),
    (
        "Instagram Token",
        "MEDIUM",
        re.compile(r"(?:INSTAGRAM_ACCESS_TOKEN|INSTAGRAM_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Instagram access token",
    ),
    (
        "LinkedIn Token",
        "MEDIUM",
        re.compile(r"(?:LINKEDIN_CLIENT_SECRET|LINKEDIN_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "LinkedIn OAuth secret",
    ),
    (
        "Microsoft Graph Token",
        "MEDIUM",
        re.compile(r"(?:MS_GRAPH_TOKEN|MICROSOFT_GRAPH_TOKEN|AZURE_AD_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Microsoft Graph API token",
    ),

    # =====================================================================
    # MEDIUM - Payment & financial
    # =====================================================================
    (
        "PayPal Client Secret",
        "MEDIUM",
        re.compile(r"(?:PAYPAL_SECRET|PAYPAL_CLIENT_SECRET)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "PayPal client secret",
    ),
    (
        "Square Access Token",
        "MEDIUM",
        re.compile(r"(?:sq0atp-[A-Za-z0-9\-_]{22,}|SQUARE_ACCESS_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Square access token",
    ),
    (
        "Braintree Access Token",
        "MEDIUM",
        re.compile(r"(?:BRAINTREE_TOKEN|BRAINTREE_ACCESS_TOKEN)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        "Braintree access token",
    ),

    # =====================================================================
    # LOW - Informational / potential credentials
    # =====================================================================
    (
        "Email Address",
        "LOW",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "Email address (potential credential)",
    ),
    (
        "IP Address",
        "LOW",
        re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "IP address",
    ),
    (
        "AWS ARN",
        "LOW",
        re.compile(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/]+"),
        "AWS Amazon Resource Name",
    ),
    (
        "Terraform API Token",
        "LOW",
        re.compile(r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{67}"),
        "Terraform Cloud API token",
    ),
    (
        "Internal Hostname",
        "LOW",
        re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:internal|local|corp|intranet|private|lan)\b", re.IGNORECASE),
        "Internal/private hostname",
    ),
    (
        "Hardcoded IP with Port",
        "LOW",
        re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{2,5}\b"),
        "Hardcoded IP:port combination",
    ),
    (
        "Debug Mode Enabled",
        "LOW",
        re.compile(r"(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG|NODE_ENV)\s*[:=]\s*(?:true|1|yes|on)", re.IGNORECASE),
        "Debug mode may expose sensitive data",
    ),
    (
        "Default Credentials Reference",
        "LOW",
        re.compile(r"(?:admin|root|user|test|guest|default)[:=][^\s]*(?:password|passwd|pwd|pass)[:=][^\s]*(?:admin|root|user|test|guest|default)", re.IGNORECASE),
        "Possible default credentials",
    ),
    (
        "Base64 Encoded Secret",
        "LOW",
        re.compile(r"(?:secret|password|token|key|credential)[\s:=]+['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", re.IGNORECASE),
        "Base64-encoded value near sensitive keyword",
    ),
    (
        "Hex Encoded Secret",
        "LOW",
        re.compile(r"(?:secret|password|token|key|credential)[\s:=]+['\"]([0-9a-fA-F]{32,})['\"]", re.IGNORECASE),
        "Hex-encoded value near sensitive keyword",
    ),
]

# Severity display colors
SEVERITY_COLORS = {
    "CRITICAL": Colors.RED + Colors.BOLD,
    "HIGH": Colors.RED,
    "MEDIUM": Colors.YELLOW,
    "LOW": Colors.BLUE,
}

# Skip these file extensions (binary / media / irrelevant)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".class",
    ".o", ".a",
    ".db", ".sqlite", ".sqlite3",
}

# Max file size to scan (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


class Finding:
    """A single sensitive data finding."""

    def __init__(self, file_path, line_number, pattern_name, severity,
                 matched_text, description):
        self.file_path = file_path
        self.line_number = line_number
        self.pattern_name = pattern_name
        self.severity = severity
        self.matched_text = matched_text
        self.description = description

    def to_dict(self):
        return {
            "file": self.file_path,
            "line": self.line_number,
            "pattern": self.pattern_name,
            "severity": self.severity,
            "match": self.matched_text[:200],  # Truncate long matches
            "description": self.description,
        }

    def __str__(self):
        color = SEVERITY_COLORS.get(self.severity, "")
        try:
            return (
                f"  {color}[{self.severity}]{Colors.END} "
                f"{self.pattern_name} in {self.file_path}:{self.line_number}\n"
                f"    Match: {self.matched_text[:120]}"
            )
        except UnicodeEncodeError:
            return (
                f"  [{self.severity}] "
                f"{self.pattern_name} in {self.file_path}:{self.line_number}\n"
                f"    Match: {self.matched_text[:120]}"
            )


class Scanner:
    """Scans files for sensitive data using regex patterns."""

    def __init__(self, scan_dir, output_file=None, min_severity=None):
        """
        Args:
            scan_dir: Directory to scan for sensitive data.
            output_file: File to save scan results (JSON format).
            min_severity: Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW).
        """
        self.scan_dir = os.path.abspath(scan_dir)
        self.output_file = output_file
        self.min_severity = min_severity or "LOW"

        # Severity ordering for filtering
        self._severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        # Results
        self.findings = []
        self.files_scanned = 0
        self.files_skipped = 0

    def _should_skip_file(self, file_path):
        """Check if a file should be skipped."""
        _, ext = os.path.splitext(file_path.lower())
        if ext in SKIP_EXTENSIONS:
            return True
        # Skip hidden files (but keep .env, .htpasswd, etc.)
        basename = os.path.basename(file_path)
        if basename.startswith(".") and basename not in (
            ".env", ".htpasswd", ".htaccess", ".netrc",
            ".git-credentials", ".npmrc", ".dockerenv",
        ):
            return True
        return False

    def _is_severity_above(self, severity):
        """Check if severity meets the minimum threshold."""
        return self._severity_order.get(severity, 99) <= self._severity_order.get(
            self.min_severity, 99
        )

    def _scan_file(self, file_path):
        """Scan a single file for sensitive patterns.

        Returns:
            List of Finding objects.
        """
        findings = []

        # Get relative path for display
        try:
            rel_path = os.path.relpath(file_path, self.scan_dir)
        except ValueError:
            rel_path = file_path

        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                self.files_skipped += 1
                return findings
        except OSError:
            self.files_skipped += 1
            return findings

        # Read file content
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            self.files_skipped += 1
            return findings

        if not content:
            return findings

        # Check each pattern
        lines = content.split("\n")
        for pattern_name, severity, regex, description in PATTERNS:
            if not self._is_severity_above(severity):
                continue

            for i, line in enumerate(lines, 1):
                matches = regex.findall(line)
                for match in matches:
                    match_text = match if isinstance(match, str) else str(match)
                    findings.append(Finding(
                        file_path=rel_path,
                        line_number=i,
                        pattern_name=pattern_name,
                        severity=severity,
                        matched_text=match_text.strip(),
                        description=description,
                    ))

        self.files_scanned += 1
        return findings

    def scan(self):
        """Execute the scan on all files in the target directory.

        Returns:
            Tuple of (success_bool, findings_list).
        """
        print_section("Sensitive Data Scan")
        print_info(f"Target: {self.scan_dir}")
        if self.output_file:
            print_info(f"Output: {self.output_file}")
        print()

        start_time = time.time()

        if not os.path.isdir(self.scan_dir):
            print_error(f"Directory not found: {self.scan_dir}")
            return False, []

        # Collect all files to scan
        all_files = []
        for root, dirs, files in os.walk(self.scan_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not self._should_skip_file(fpath):
                    all_files.append(fpath)

        print_info(f"Found {len(all_files)} file(s) to scan")
        print()

        # Scan files
        progress = ProgressBar(len(all_files), desc="Scanning")

        for fpath in all_files:
            file_findings = self._scan_file(fpath)
            self.findings.extend(file_findings)
            progress.update()

        progress.finish()

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        # Display results
        elapsed = time.time() - start_time

        if not self.findings:
            print_success("No sensitive data found.")
        else:
            # Group by severity
            by_severity = defaultdict(list)
            for f in self.findings:
                by_severity[f.severity].append(f)

            print_section("Scan Results")

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity not in by_severity:
                    continue
                items = by_severity[severity]
                color = SEVERITY_COLORS.get(severity, "")
                try:
                    print(f"\n  {color}{Colors.BOLD}{severity} ({len(items)} finding(s)):{Colors.END}")
                except UnicodeEncodeError:
                    print(f"\n  {severity} ({len(items)} finding(s)):")

                for item in items:
                    print(str(item))
                    print()

        # Summary
        print_section("Scan Summary")
        print_success(f"Files scanned: {self.files_scanned}")
        print_success(f"Files skipped: {self.files_skipped}")

        if self.findings:
            by_severity = defaultdict(int)
            for f in self.findings:
                by_severity[f.severity] += 1
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in by_severity:
                    color = SEVERITY_COLORS.get(sev, "")
                    try:
                        print(f"  {color}[{sev}]{Colors.END}: {by_severity[sev]}")
                    except UnicodeEncodeError:
                        print(f"  [{sev}]: {by_severity[sev]}")

        print_success(f"Time elapsed: {elapsed:.1f}s")

        # Save results to file
        if self.output_file:
            self._save_results()

        return True, self.findings

    def _save_results(self):
        """Save scan results to a JSON file."""
        try:
            safe_makedirs(os.path.dirname(self.output_file) or ".")

            report = {
                "tool": "GitSheriff Scanner",
                "scan_dir": self.scan_dir,
                "total_findings": len(self.findings),
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "findings": [f.to_dict() for f in self.findings],
            }

            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print_success(f"Results saved to {self.output_file}")

        except Exception as e:
            print_error(f"Failed to save results: {e}")
