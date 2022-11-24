package static

import "embed"

//go:embed frontend/*
var FrontendFile embed.FS
