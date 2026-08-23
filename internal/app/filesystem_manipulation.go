package app

import "github.com/inguardians/peirates/internal/modules/filesystem"

func displayFile(path string) error        { return filesystem.DisplayFile(path) }
func listDirectory(path string) error      { return filesystem.ListDirectory(path) }
func changeDirectory(path string) error    { return filesystem.ChangeDirectory(path) }
func getCurrentDirectory() (string, error) { return filesystem.CurrentDirectory() }
