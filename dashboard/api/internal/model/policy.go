package model

import "time"

type Policy struct {
	ID        string    `json:"id"`
	Version   string    `json:"version"`
	Content   string    `json:"content"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
