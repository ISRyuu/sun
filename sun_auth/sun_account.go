package sun_auth

import (
	"fmt"
	"log"

	"github.com/go-pg/pg/v9"
	"github.com/go-pg/pg/v9/orm"
)

// user account ORM
type User struct {
	OpenId   string
	Password string
	Salt     string
}

type sunAccount struct {
	db *pg.DB
}

func createSchema(db *pg.DB, schemas []interface{}) {
	for _, model := range schemas {
		err := db.CreateTable(model, &orm.CreateTableOptions{IfNotExists: true})
		fatal(err, fmt.Sprintf("cannot create schemas %t", model))
	}
}

func (sa *sunAccount) connectDB(dbURL string) {
	log.Println("connect db")
	options, error := pg.ParseURL(dbURL)
	fatal(error, "cannot parser pg url")
	pgcon := pg.Connect(options)
	createSchema(pgcon, []interface{}{(*User)(nil)})
}
