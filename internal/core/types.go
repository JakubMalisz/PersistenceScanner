package core

import (
	"os"
	"time"
)

type FileData struct {
	Name        string      `json:"name,omitempty"`
	Path        string      `json:"path,omitempty"`
	Size        uint        `json:"file_size,omitempty"`
	Permissions os.FileMode `json:"permissions,omitempty"`
	//CreateTime  time.Time   `json:"creation_time"`
	ModTime      time.Time `json:"last_modification,omitempty"`
	ParsedData any `json:"parsed_data,omitempty"`
}

type DetectionRule struct{
	Pattern string
	Description string
	Severity string
}

type Alert struct{
	FilePath string
	Description string
	Severity string
	Pattern string
	ExtraInfo string
}