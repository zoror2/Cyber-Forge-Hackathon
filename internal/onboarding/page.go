package onboarding

import (
	"configbridge/pkg/config"
	"configbridge/pkg/model"
	_ "embed"
	"html/template"
	"io"
	"net/url"
)

//go:embed page.html
var markup string

//go:embed style.css
var CSS string
var page = template.Must(template.New("onboarding").Funcs(template.FuncMap{"isID": func(s string) bool { return s == "id" }}).Parse(markup))

type View struct {
	Token             string
	Entity            string
	Fields            []MappingRow
	NotificationReady bool
	Issues            []config.Issue
	JSON              string
	ID                string
	Revision          int
	Saved             bool
	Tested            bool
	Result            *model.Run
	Values            url.Values
	SecretNames       []string
}

func Render(w io.Writer, v View) error { return page.Execute(w, v) }
