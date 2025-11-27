package migrations

import "github.com/devchuckcamp/goauthx/pkg/config"

func getCreateUsersTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE users (
	id VARCHAR(36) PRIMARY KEY,
	email VARCHAR(255) NOT NULL UNIQUE,
	password_hash VARCHAR(255) NOT NULL,
	first_name VARCHAR(100),
	last_name VARCHAR(100),
	active BOOLEAN NOT NULL DEFAULT TRUE,
	email_verified BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	INDEX idx_users_email (email),
	INDEX idx_users_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE users (
	id VARCHAR(36) PRIMARY KEY,
	email VARCHAR(255) NOT NULL UNIQUE,
	password_hash VARCHAR(255) NOT NULL,
	first_name VARCHAR(100),
	last_name VARCHAR(100),
	active BOOLEAN NOT NULL DEFAULT TRUE,
	email_verified BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(active);
`
	case config.SQLServer:
		return `
CREATE TABLE users (
	id NVARCHAR(36) PRIMARY KEY,
	email NVARCHAR(255) NOT NULL UNIQUE,
	password_hash NVARCHAR(255) NOT NULL,
	first_name NVARCHAR(100),
	last_name NVARCHAR(100),
	active BIT NOT NULL DEFAULT 1,
	email_verified BIT NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	updated_at DATETIME NOT NULL DEFAULT GETDATE()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(active);
`
	default:
		return ""
	}
}

func getCreateRolesTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE roles (
	id VARCHAR(36) PRIMARY KEY,
	name VARCHAR(100) NOT NULL UNIQUE,
	description TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	INDEX idx_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE roles (
	id VARCHAR(36) PRIMARY KEY,
	name VARCHAR(100) NOT NULL UNIQUE,
	description TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_roles_name ON roles(name);
`
	case config.SQLServer:
		return `
CREATE TABLE roles (
	id NVARCHAR(36) PRIMARY KEY,
	name NVARCHAR(100) NOT NULL UNIQUE,
	description NVARCHAR(MAX),
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	updated_at DATETIME NOT NULL DEFAULT GETDATE()
);

CREATE INDEX idx_roles_name ON roles(name);
`
	default:
		return ""
	}
}

func getCreatePermissionsTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE permissions (
	id VARCHAR(36) PRIMARY KEY,
	name VARCHAR(100) NOT NULL UNIQUE,
	resource VARCHAR(100) NOT NULL,
	action VARCHAR(50) NOT NULL,
	description TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	INDEX idx_permissions_name (name),
	INDEX idx_permissions_resource (resource)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE permissions (
	id VARCHAR(36) PRIMARY KEY,
	name VARCHAR(100) NOT NULL UNIQUE,
	resource VARCHAR(100) NOT NULL,
	action VARCHAR(50) NOT NULL,
	description TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);
`
	case config.SQLServer:
		return `
CREATE TABLE permissions (
	id NVARCHAR(36) PRIMARY KEY,
	name NVARCHAR(100) NOT NULL UNIQUE,
	resource NVARCHAR(100) NOT NULL,
	action NVARCHAR(50) NOT NULL,
	description NVARCHAR(MAX),
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	updated_at DATETIME NOT NULL DEFAULT GETDATE()
);

CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);
`
	default:
		return ""
	}
}

func getCreateUserRolesTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE user_roles (
	user_id VARCHAR(36) NOT NULL,
	role_id VARCHAR(36) NOT NULL,
	assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, role_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
	INDEX idx_user_roles_user_id (user_id),
	INDEX idx_user_roles_role_id (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE user_roles (
	user_id VARCHAR(36) NOT NULL,
	role_id VARCHAR(36) NOT NULL,
	assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, role_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
`
	case config.SQLServer:
		return `
CREATE TABLE user_roles (
	user_id NVARCHAR(36) NOT NULL,
	role_id NVARCHAR(36) NOT NULL,
	assigned_at DATETIME NOT NULL DEFAULT GETDATE(),
	PRIMARY KEY (user_id, role_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
`
	default:
		return ""
	}
}

func getCreateRolePermissionsTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE role_permissions (
	role_id VARCHAR(36) NOT NULL,
	permission_id VARCHAR(36) NOT NULL,
	granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (role_id, permission_id),
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
	FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
	INDEX idx_role_permissions_role_id (role_id),
	INDEX idx_role_permissions_permission_id (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE role_permissions (
	role_id VARCHAR(36) NOT NULL,
	permission_id VARCHAR(36) NOT NULL,
	granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (role_id, permission_id),
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
	FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
`
	case config.SQLServer:
		return `
CREATE TABLE role_permissions (
	role_id NVARCHAR(36) NOT NULL,
	permission_id NVARCHAR(36) NOT NULL,
	granted_at DATETIME NOT NULL DEFAULT GETDATE(),
	PRIMARY KEY (role_id, permission_id),
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
	FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
`
	default:
		return ""
	}
}

func getCreateRefreshTokensTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE refresh_tokens (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	token VARCHAR(255) NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at TIMESTAMP NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_refresh_tokens_token (token),
	INDEX idx_refresh_tokens_user_id (user_id),
	INDEX idx_refresh_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE refresh_tokens (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	token VARCHAR(255) NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at TIMESTAMP NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
`
	case config.SQLServer:
		return `
CREATE TABLE refresh_tokens (
	id NVARCHAR(36) PRIMARY KEY,
	user_id NVARCHAR(36) NOT NULL,
	token NVARCHAR(255) NOT NULL UNIQUE,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	revoked_at DATETIME NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
`
	default:
		return ""
	}
}

func getCreateEmailVerificationsTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE email_verifications (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	token VARCHAR(255) NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	used_at TIMESTAMP NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_email_verifications_token (token),
	INDEX idx_email_verifications_user_id (user_id),
	INDEX idx_email_verifications_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE email_verifications (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	token VARCHAR(255) NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	used_at TIMESTAMP NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_email_verifications_token ON email_verifications(token);
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
`
	case config.SQLServer:
		return `
CREATE TABLE email_verifications (
	id NVARCHAR(36) PRIMARY KEY,
	user_id NVARCHAR(36) NOT NULL,
	token NVARCHAR(255) NOT NULL UNIQUE,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	used_at DATETIME NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_email_verifications_token ON email_verifications(token);
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
`
	default:
		return ""
	}
}

func getDropEmailVerificationsTableSQL(driver config.DatabaseDriver) string {
	return "DROP TABLE IF EXISTS email_verifications;"
}

func getCreatePasswordResetsTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE password_resets (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	token VARCHAR(255) NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	used_at TIMESTAMP NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_password_resets_token (token),
	INDEX idx_password_resets_user_id (user_id),
	INDEX idx_password_resets_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE password_resets (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	token VARCHAR(255) NOT NULL UNIQUE,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	used_at TIMESTAMP NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_password_resets_token ON password_resets(token);
CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
CREATE INDEX idx_password_resets_expires_at ON password_resets(expires_at);
`
	case config.SQLServer:
		return `
CREATE TABLE password_resets (
	id NVARCHAR(36) PRIMARY KEY,
	user_id NVARCHAR(36) NOT NULL,
	token NVARCHAR(255) NOT NULL UNIQUE,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	used_at DATETIME NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_password_resets_token ON password_resets(token);
CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
CREATE INDEX idx_password_resets_expires_at ON password_resets(expires_at);
`
	default:
		return ""
	}
}

func getDropPasswordResetsTableSQL(driver config.DatabaseDriver) string {
	return "DROP TABLE IF EXISTS password_resets;"
}

func getAddEmailVerifiedColumnSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return "ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;"
	case config.Postgres:
		return "ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;"
	case config.SQLServer:
		return "ALTER TABLE users ADD email_verified BIT NOT NULL DEFAULT 0;"
	default:
		return ""
	}
}

func getDropEmailVerifiedColumnSQL(driver config.DatabaseDriver) string {
	return "ALTER TABLE users DROP COLUMN email_verified;"
}

func getCreateOAuthAccountsTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `
CREATE TABLE oauth_accounts (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	provider VARCHAR(50) NOT NULL,
	provider_id VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	name VARCHAR(255),
	picture VARCHAR(512),
	access_token TEXT,
	refresh_token TEXT,
	expires_at TIMESTAMP NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	UNIQUE KEY idx_oauth_provider_id (provider, provider_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_oauth_user_id (user_id),
	INDEX idx_oauth_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
	case config.Postgres:
		return `
CREATE TABLE oauth_accounts (
	id VARCHAR(36) PRIMARY KEY,
	user_id VARCHAR(36) NOT NULL,
	provider VARCHAR(50) NOT NULL,
	provider_id VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	name VARCHAR(255),
	picture VARCHAR(512),
	access_token TEXT,
	refresh_token TEXT,
	expires_at TIMESTAMP NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (provider, provider_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_oauth_user_id ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_email ON oauth_accounts(email);
`
	case config.SQLServer:
		return `
CREATE TABLE oauth_accounts (
	id NVARCHAR(36) PRIMARY KEY,
	user_id NVARCHAR(36) NOT NULL,
	provider NVARCHAR(50) NOT NULL,
	provider_id NVARCHAR(255) NOT NULL,
	email NVARCHAR(255) NOT NULL,
	name NVARCHAR(255),
	picture NVARCHAR(512),
	access_token NVARCHAR(MAX),
	refresh_token NVARCHAR(MAX),
	expires_at DATETIME NULL,
	created_at DATETIME NOT NULL DEFAULT GETDATE(),
	updated_at DATETIME NOT NULL DEFAULT GETDATE(),
	UNIQUE (provider, provider_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_oauth_user_id ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_email ON oauth_accounts(email);
`
	default:
		return ""
	}
}

func getDropOAuthAccountsTableSQL(driver config.DatabaseDriver) string {
	return "DROP TABLE IF EXISTS oauth_accounts;"
}
