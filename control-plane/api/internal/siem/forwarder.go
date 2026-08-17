package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

type Backend string

const (
	Splunk     Backend = "splunk"
	Datadog    Backend = "datadog"
	OpenSearch Backend = "opensearch"
	Local      Backend = "local"
)

func ParseBackend(s string) Backend {
	switch strings.ToLower(s) {
	case "splunk":
		return Splunk
	case "datadog":
		return Datadog
	case "opensearch":
		return OpenSearch
	default:
		return Local
	}
}

type Config struct {
	Backend     Backend
	Endpoint    string
	Token       string
	Timeout     time.Duration
	BatchSize   int
	FlushPeriod time.Duration
	OrgID       string
}

type EnrichedEvent struct {
	*model.RedactedEvent
	GatewayID string    `json:"gateway_id"`
	OrgID     string    `json:"org_id"`
	Ingested  time.Time `json:"ingested_at"`
}

type Forwarder struct {
	cfg        Config
	client     *http.Client
	eventChan  chan *EnrichedEvent
	wg         sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewForwarder(cfg Config) *Forwarder {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushPeriod <= 0 {
		cfg.FlushPeriod = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	f := &Forwarder{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		eventChan:  make(chan *EnrichedEvent, 10000),
		ctx:        ctx,
		cancelFunc: cancel,
	}

	if cfg.Backend != Local && cfg.Endpoint != "" {
		f.wg.Add(1)
		go f.workerLoop()
	}

	return f
}

func (f *Forwarder) Enqueue(event *model.RedactedEvent, gatewayID string) {
	if f.cfg.Backend == Local || f.cfg.Endpoint == "" {
		return
	}

	enriched := &EnrichedEvent{
		RedactedEvent: event,
		GatewayID:     gatewayID,
		OrgID:         f.cfg.OrgID,
		Ingested:      time.Now().UTC(),
	}

	select {
	case f.eventChan <- enriched:
	default:
		log.Printf("siem forwarder queue full, dropping event %s", event.EventID)
	}
}

func (f *Forwarder) workerLoop() {
	defer f.wg.Done()

	batch := make([]*EnrichedEvent, 0, f.cfg.BatchSize)
	ticker := time.NewTicker(f.cfg.FlushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			f.flush(batch)
			return
		case evt, ok := <-f.eventChan:
			if !ok {
				f.flush(batch)
				return
			}
			batch = append(batch, evt)
			if len(batch) >= f.cfg.BatchSize {
				f.flush(batch)
				batch = make([]*EnrichedEvent, 0, f.cfg.BatchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				f.flush(batch)
				batch = make([]*EnrichedEvent, 0, f.cfg.BatchSize)
			}
		}
	}
}

func (f *Forwarder) flush(batch []*EnrichedEvent) {
	if len(batch) == 0 {
		return
	}

	var err error
	switch f.cfg.Backend {
	case Splunk:
		err = f.sendSplunk(batch)
	case Datadog:
		err = f.sendDatadog(batch)
	case OpenSearch:
		err = f.sendOpenSearch(batch)
	}

	if err != nil {
		log.Printf("siem export to %s failed for %d events: %v", f.cfg.Backend, len(batch), err)
	}
}

func (f *Forwarder) sendSplunk(batch []*EnrichedEvent) error {
	var buf bytes.Buffer
	for _, evt := range batch {
		payload := map[string]interface{}{
			"time":       evt.TimestampMs / 1000,
			"sourcetype": "agentcontrol-hub",
			"source":     "agentcontrol-control-plane",
			"event":      evt,
		}
		data, _ := json.Marshal(payload)
		buf.Write(data)
		buf.WriteString("\n")
	}

	req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.cfg.Endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", f.cfg.Token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("splunk HTTP %d", resp.StatusCode)
	}
	return nil
}

func (f *Forwarder) sendDatadog(batch []*EnrichedEvent) error {
	var datadogEvents []map[string]interface{}
	for _, evt := range batch {
		datadogEvents = append(datadogEvents, map[string]interface{}{
			"ddsource": "agentcontrol",
			"service":  "agentcontrol-hub",
			"hostname": evt.GatewayID,
			"message":  evt,
			"org_id":   evt.OrgID,
		})
	}

	data, err := json.Marshal(datadogEvents)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.cfg.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("DD-API-KEY", f.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("datadog HTTP %d", resp.StatusCode)
	}
	return nil
}

func (f *Forwarder) sendOpenSearch(batch []*EnrichedEvent) error {
	for _, evt := range batch {
		data, err := json.Marshal(evt)
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.cfg.Endpoint, bytes.NewReader(data))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if strings.Contains(f.cfg.Token, ":") {
			parts := strings.SplitN(f.cfg.Token, ":", 2)
			req.SetBasicAuth(parts[0], parts[1])
		} else if f.cfg.Token != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", f.cfg.Token))
		}

		resp, err := f.client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
	return nil
}

func (f *Forwarder) Close() {
	f.cancelFunc()
	close(f.eventChan)
	f.wg.Wait()
}
