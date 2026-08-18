package migrations

import (
	"github.com/jmoiron/sqlx"
	"github.com/knadh/koanf/v2"
	"github.com/knadh/stuffbin"
)

// V2_7_2 adds the optional `app.set_password_url_base` setting, which lets a
// deployment point password set/reset email links at its own page. Empty
// (the default) keeps the current behaviour: `{root_url}/set-password`.
func V2_7_2(db *sqlx.DB, fs stuffbin.FileSystem, ko *koanf.Koanf) error {
	if _, err := db.Exec(`INSERT INTO settings ("key", value) VALUES ('app.set_password_url_base', '""'::jsonb) ON CONFLICT ("key") DO NOTHING;`); err != nil {
		return err
	}
	return nil
}
