package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"teamacedia/backend/internal/config"
)

func SendWebhook(message string) error {
	payload := map[string]string{
		"content":  "```ansi\n\033[36m" + message + "\n```",
		"username": config.Config.LoggerWebhookUsername,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(config.Config.LoggerWebhookUrl, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %s", resp.Status)
	}
	return nil
}

func LogEvent(event string) {
	log.Println(event)
	err := SendWebhook(event)
	if err != nil {
		fmt.Printf("Failed to send Discord webhook: %v\n", err)
	}
}

func LogEventf(format string, args ...interface{}) {
	event := fmt.Sprintf(format, args...)
	LogEvent(event)
}
