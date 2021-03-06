package sun_auth

import (
	"fmt"
	"log"

	"github.com/go-pg/pg/v9"
	"github.com/go-pg/pg/v9/orm"
)

type User struct {
	Id        string `pg:"default:gen_random_uuid(),pk"`
	Username  string `pg:",unique:idx_username_projectid,type:varchar(16),notnull"`
	Password  string `pg:",notnull"`
	ProjectId string `pg:",unique:idx_username_projectid,type:varchar(16),on_delete:CASCADE"`
	Project   *Project
}

type Project struct {
	ProjectId   string `pg:",type:varchar(16),pk"`
	ProjectName string `pg:",type:varchar(16)"`
	Secret      string
}

type sunAccount struct {
	db *pg.DB
}

func NewSunAccount(dbURL string) *sunAccount {
	options, error := pg.ParseURL(dbURL)
	fatal(error, "cannot parser pg url")
	return &sunAccount{
		db: pg.Connect(options),
	}
}

// create new user, this function will replace the Password field in parameter `user`
// with the hashed one (the one which is stored in database)
func (sa *sunAccount) NewUser(user *User) error {
	user.Password = PasswordHash(user.Password, user.Id)
	return sa.db.Insert(user)
}

// authenticate user by username and password, return user on success
func (sa *sunAccount) AuthUser(user *User) (*User, error) {
	tuser := &User{}
	err := sa.db.Model(tuser).
		Where("username = ? and project_id = ?", user.Username, user.ProjectId).
		Select()
	if err != nil {
		log.Printf("error authuser :: %v", err)
		return nil, fmt.Errorf("no such user")
	}
	passwd := PasswordHash(user.Password, tuser.Id)
	if tuser.Password != passwd {
		return nil, fmt.Errorf("password not match ")
	}

	return tuser, nil
}

func (sa *sunAccount) GetUserById(id string) (*User, error) {

	user := &User{Id: id}
	if err := sa.db.Select(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (sa *sunAccount) GetUserByUsername(name string) (*User, error) {

	user := &User{Username: name}
	if err := sa.db.Select(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (sa *sunAccount) UpdateUser(user *User) error {
	return sa.db.Update(user)
}

func (sa *sunAccount) DeleteUser(user *User) error {
	return sa.db.Delete(user)
}

func (sa *sunAccount) NewProject(proj *Project) error {
	return sa.db.Insert(proj)
}

func (sa *sunAccount) GetProjectByPid(pid string) (*Project, error) {

	proj := &Project{ProjectId: pid}
	if err := sa.db.Select(proj); err != nil {
		return nil, err
	}

	return proj, nil
}

// check ProjectId and ProjectSecret
func (sa *sunAccount) AuthProject(proj *Project) (*Project, error) {
	tproj := &Project{
		ProjectId: proj.ProjectId,
	}
	error := sa.db.Select(tproj)
	if error != nil {
		log.Printf("error select project :: %v", error)
		return nil, fmt.Errorf("no such project")
	}

	if tproj.Secret != proj.Secret {
		return nil, fmt.Errorf("project secret not match")
	}

	return tproj, nil
}

func (sa *sunAccount) UpdateProject(proj *Project) error {
	return sa.db.Update(proj)
}

func (sa *sunAccount) DeleteProject(proj *Project) error {
	return sa.db.Delete(proj)
}

// initialize database
func (sa *sunAccount) InitDB() {
	log.Println("init db")
	createSchema(sa.db, []interface{}{(*Project)(nil), (*User)(nil)})
}

// create all tables
func createSchema(db *pg.DB, schemas []interface{}) {
	for _, model := range schemas {
		err := db.CreateTable(model, &orm.CreateTableOptions{
			IfNotExists:   true,
			FKConstraints: true,
		})
		fatal(err, fmt.Sprintf("cannot create schemas %t", model))
	}
}
