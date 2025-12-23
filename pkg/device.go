package api

import "time"

type Device struct {
	PublicKey  string
	Name       string
	OSName     string
	ApiKey     string
	IpMode     StatusIP
	AssignedIP string
	LastSeen   time.Time
	IsActive   bool
	AppVersion string
}

type StatusIP int

const (
	Static StatusIP = iota
	Dynamic
)
