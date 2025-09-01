package asset_manager

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"teamacedia/backend/internal/models"

	"gopkg.in/ini.v1"
)

var Capes []models.Cape

// LoadCapes scans the folder and returns a list of capes (only complete pairs + config).
func LoadCapes(folder string) ([]models.Cape, error) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil, fmt.Errorf("failed to read folder: %w", err)
	}

	textures := make(map[string]string)
	previews := make(map[string]string)
	animLengths := make(map[string]int)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(folder, name)

		switch {
		case strings.HasSuffix(name, "_texture.png"):
			id := strings.TrimSuffix(name, "_texture.png")
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %s: %w", name, err)
			}
			textures[id] = base64.StdEncoding.EncodeToString(data)

		case strings.HasSuffix(name, "_preview.png"):
			id := strings.TrimSuffix(name, "_preview.png")
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %s: %w", name, err)
			}
			previews[id] = base64.StdEncoding.EncodeToString(data)

		case strings.HasSuffix(name, "_config.ini"):
			id := strings.TrimSuffix(name, "_config.ini")
			cfg, err := ini.Load(path)
			if err != nil {
				return nil, fmt.Errorf("failed to load ini file %s: %w", name, err)
			}
			animLengths[id] = cfg.Section("").Key("anim_length").MustInt(1) // default 1
		}
	}

	var capes []models.Cape
	for id, tex := range textures {
		preview, ok := previews[id]
		if !ok {
			continue // skip incomplete capes
		}
		length := animLengths[id]
		if length == 0 {
			length = 1
		}
		capes = append(capes, models.Cape{
			CapeID:         id,
			CapeTexture:    tex,
			CapePreview:    preview,
			CapeAnimLength: length,
		})
	}

	// Sort results for stability
	sort.Slice(capes, func(i, j int) bool {
		return capes[i].CapeID < capes[j].CapeID
	})

	return capes, nil
}
