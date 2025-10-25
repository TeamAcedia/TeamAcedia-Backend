package config

import (
	"teamacedia/backend/internal/models"

	"gopkg.in/ini.v1"
)

var Config *models.Config

// LoadConfig loads Config from an INI file
func LoadConfig(path string) (*models.Config, error) {
	cfgFile, err := ini.Load(path)
	if err != nil {
		return nil, err
	}

	cfg := &models.Config{
		TokenValidDurationHours: cfgFile.Section("").Key("TokenValidDurationHours").MustInt(12),
		DefaultCapeIDs:          cfgFile.Section("").Key("DefaultCapeIDs").String(),
		LoggerWebhookUrl:        cfgFile.Section("").Key("LoggerWebhookUrl").String(),
		LoggerWebhookUsername:   cfgFile.Section("").Key("LoggerWebhookUsername").String(),
	}

	return cfg, nil
}
