package nb5

import (
	"database/sql"
	"embed"
	"io"
	"os"

	"github.com/bokwoon95/sq"
	"github.com/bokwoon95/sqddl/ddl"
)

//go:embed schema.go
var schemaFS embed.FS

func automigrate(dialect string, db *sql.DB) error {
	if db == nil {
		return nil
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             db,
		Dialect:        dialect,
		DirFS:          schemaFS,
		Filenames:      []string{"schema.go"},
		DropObjects:    true,
		AcceptWarnings: true,
		DryRun:         true,
		Stdout:         os.Stderr,
	}
	err := automigrateCmd.Run()
	if err != nil {
		return err
	}
	automigrateCmd.DryRun = false
	automigrateCmd.Stderr = io.Discard
	err = automigrateCmd.Run()
	if err != nil {
		return err
	}
	return nil
}

type USERS struct {
	sq.TableStruct
	USER_ID          sq.UUIDField   `ddl:"primarykey"`
	EMAIL            sq.StringField `ddl:"notnull len=500 unique"`
	PASSWORD_HASH    sq.StringField `ddl:"notnull len=500"`
	DISPLAY_NAME     sq.StringField `ddl:"len=500"`
	RESET_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) unique"`
}

type SESSIONS struct {
	sq.TableStruct
	SESSION_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) primarykey"`
	SESSION_TOKEN      sq.BinaryField `ddl:"mysql:type=BINARY(24)"`
	LOGIN_TOKEN_HASH   sq.BinaryField `ddl:"mysql:type=BINARY(40) unique"`
	DOMAINS_TO_LOGIN   sq.JSONField
	USER_ID            sq.UUIDField `ddl:"notnull references={users onupdate=cascade index}"`
}

type SITES struct {
	sq.TableStruct
	SITE_ID   sq.UUIDField   `ddl:"primarykey"`
	SITE_NAME sq.StringField `ddl:"notnull len=500 unique"` // only lowercase letters, digits and hyphen
	SEQ       sq.NumberField
	USER_ID   sq.UUIDField `ddl:"notnull references={users onupdate=cascade index}"`
}

type FLASH_SESSIONS struct {
	sq.TableStruct
	SESSION_ID sq.UUIDField `ddl:"primarykey"`
	PAYLOAD    sq.BinaryField
}
