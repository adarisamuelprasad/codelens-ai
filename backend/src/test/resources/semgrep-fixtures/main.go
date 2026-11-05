package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// codelens-expect: SQL_INJECTION
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	// codelens-expect: SQL_INJECTION
	db.Exec("DELETE FROM users WHERE id = " + id)
	ok, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
	_ = rows
	_ = ok

	// codelens-expect: COMMAND_INJECTION
	exec.Command("sh", "-c", "ping "+r.URL.Query().Get("host")).Run()
	exec.Command("ping", "-c", "1", r.URL.Query().Get("host")).Run()
	exec.Command("sh", "-c", "uptime").Run()

	// codelens-expect: PERMISSIVE_CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "https://devert.in")

	name := r.URL.Query().Get("name")
	// codelens-expect: UNSAFE_HTML
	t := template.HTML(name)
	_ = t
}

func client() *http.Client {
	tr := &http.Transport{
		// codelens-expect: TLS_VERIFY_DISABLED
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func readAll(paths []string) error {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		// codelens-expect: DEFER_IN_LOOP
		defer f.Close()
	}
	for _, p := range paths {
		func() {
			f, _ := os.Open(p)
			defer f.Close()
		}()
	}
	f, err := os.Open("x")
	// codelens-expect: SWALLOWED_EXCEPTION
	if err != nil {
	}
	defer f.Close()
	return nil
}
