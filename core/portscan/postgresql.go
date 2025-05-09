package portscan

import (
	"context"
	"database/sql"
	"fmt"
	"slack-wails/lib/gologger"
	"slack-wails/lib/structs"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func PostgresScan(ctx, ctrlCtx context.Context, taskId, host string, usernames, passwords []string) {
	for _, user := range usernames {
		for _, pass := range passwords {
			if ctrlCtx.Err() != nil {
				gologger.Warning(ctx, "[postgres] User exits crack scanning")
				return
			}
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag, err := PostgresConn(host, user, pass)
			if flag && err == nil {
				runtime.EventsEmit(ctx, "nucleiResult", structs.VulnerabilityInfo{
					TaskId:   taskId,
					ID:       "postgres weak password",
					Name:     "postgres weak password",
					URL:      host,
					Type:     "Postgres",
					Severity: "HIGH",
					Extract:  user + "/" + pass,
				})
				return
			} else {
				gologger.Info(ctx, fmt.Sprintf("postgres://%s %s:%s is login failed", host, user, pass))
			}
		}
	}
}

func PostgresConn(host, user, pass string) (flag bool, err error) {
	flag = false
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v/postgres?sslmode=disable", user, pass, host)
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(10 * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			flag = true
		}
	}
	return flag, err
}
