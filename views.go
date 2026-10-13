package main

import (
	"html/template"
)

type AlertView struct {
	ID                      int64
	Ts, SIEM, Source, Title string
	SevClass, SevLabel      string
	Pills                   []string
}

type BookView struct {
	Name, Description                 string
	Enabled, IsCustom, Edited         bool
	GateClass, GateLabel, StatusLabel string
	StatusClass                       string
}

type DashboardData struct {
	TotalAlerts, Pending, ActiveBlocks int
	Alerts                             []AlertView
}

type SelectOpt struct {
	Value    int
	Label    string
	Selected bool
}

type PlaybooksData struct {
	Books []BookView

	HasInitial     bool
	InitName       string
	InitDesc       string
	InitTemplate   string
	InitNotIPText  string
	InitEnabled    bool
	InitCustom     bool
	InitGate       string
	InitKeywords   []string
	InitActions    []string
	InitActionsJS  template.JS
	InitLocksJS    template.JS
	MinSevOptions  []SelectOpt
	DurOptions     []SelectOpt
	InitialPreview map[string]interface{}
}

type ApprovalsData struct{ Rows []Approval }

type AuditData struct{ Rows []Action }
