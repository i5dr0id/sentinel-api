package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type PostgresStore struct {
	pool *pgxpool.Pool
	log  *zerolog.Logger
}

func NewPostgres(ctx context.Context, dsn string, log *zerolog.Logger) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PostgresStore{pool: pool, log: log}, nil
}

func (p *PostgresStore) Close() { p.pool.Close() }

func (p *PostgresStore) Create(a *alerts.Alert) error {
	_, err := p.pool.Exec(context.Background(), `
		insert into sentinel_alerts
		  (id, rule_id, rule_key, title, severity, status, confidence, mitre, description,
		   asset, src_ip, geo, count, blocked_count, unique_paths, distinct_assets, event_ids,
		   started_at, last_seen_at, assignee, assigned_at, status_changed_at, responded_at,
		   resolved_at, resolution, actions, extra, created_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
		p.rowArgs(a)...)
	if err != nil {
		return fmt.Errorf("create alert: %w", err)
	}
	return nil
}

func (p *PostgresStore) Get(id string) (*alerts.Alert, error) {
	row, err := p.pool.Query(context.Background(),
		`select * from sentinel_alerts where id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	if !row.Next() {
		return nil, alerts.ErrNotFound
	}
	return p.scan(row)
}

func (p *PostgresStore) Update(a *alerts.Alert) error {
	args := p.rowArgs(a)
	args = append(args, a.ID)
	_, err := p.pool.Exec(context.Background(), `
		update sentinel_alerts set
		  rule_id=$2, rule_key=$3, title=$4, severity=$5, status=$6, confidence=$7, mitre=$8,
		  description=$9, asset=$10, src_ip=$11, geo=$12, count=$13, blocked_count=$14,
		  unique_paths=$15, distinct_assets=$16, event_ids=$17, started_at=$18, last_seen_at=$19,
		  assignee=$20, assigned_at=$21, status_changed_at=$22, responded_at=$23, resolved_at=$24,
		  resolution=$25, actions=$26, extra=$27, created_at=$28
		where id=$29`, args...)
	if err != nil {
		return fmt.Errorf("update alert: %w", err)
	}
	return nil
}

func (p *PostgresStore) rowArgs(a *alerts.Alert) []any {
	mitre := a.MITRE
	if mitre == nil {
		mitre = []string{}
	}
	eventIDs := a.EventIDs
	if eventIDs == nil {
		eventIDs = []string{}
	}
	geo, _ := json.Marshal(a.Geo)
	actions, _ := json.Marshal(a.Actions)
	var extra []byte
	if a.Extra != nil {
		extra, _ = json.Marshal(a.Extra)
	}
	return []any{
		a.ID, a.RuleID, a.RuleKey, a.Title, string(a.Severity), string(a.Status), a.Confidence,
		mitre, a.Description, a.Asset, a.SrcIP, geo, a.Count, a.BlockedCount, a.UniquePaths,
		a.DistinctAssets, eventIDs, a.StartedAt, a.LastSeenAt, a.Assignee, a.AssignedAt,
		a.StatusChangedAt, a.RespondedAt, a.ResolvedAt, string(a.Resolution), actions, extra,
		a.CreatedAt,
	}
}

func (p *PostgresStore) scan(row pgx.Rows) (*alerts.Alert, error) {
	a := &alerts.Alert{}
	var (
		severity, status, resolution string
		geoRaw, actionsRaw, extraRaw []byte
	)
	err := row.Scan(
		&a.ID, &a.RuleID, &a.RuleKey, &a.Title, &severity, &status, &a.Confidence,
		&a.MITRE, &a.Description, &a.Asset, &a.SrcIP, &geoRaw, &a.Count, &a.BlockedCount,
		&a.UniquePaths, &a.DistinctAssets, &a.EventIDs, &a.StartedAt, &a.LastSeenAt,
		&a.Assignee, &a.AssignedAt, &a.StatusChangedAt, &a.RespondedAt, &a.ResolvedAt,
		&resolution, &actionsRaw, &extraRaw, &a.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan alert: %w", err)
	}
	a.Severity = event.Severity(severity)
	a.Status = alerts.Status(status)
	a.Resolution = alerts.Resolution(resolution)
	if len(geoRaw) > 0 {
		_ = json.Unmarshal(geoRaw, &a.Geo)
	}
	if len(actionsRaw) > 0 {
		_ = json.Unmarshal(actionsRaw, &a.Actions)
	}
	if len(extraRaw) > 0 {
		_ = json.Unmarshal(extraRaw, &a.Extra)
	}
	return a, nil
}

func (p *PostgresStore) List(f alerts.Filter) ([]*alerts.Alert, error) {
	where := []string{"1=1"}
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if f.Status != "" {
		where = append(where, "status = "+arg(string(f.Status)))
	}
	if f.Severity != "" {
		where = append(where, "severity = "+arg(string(f.Severity)))
	}
	if f.Asset != "" {
		where = append(where, "asset = "+arg(f.Asset))
	}
	if f.Assignee != "" {
		where = append(where, "assignee = "+arg(f.Assignee))
	}
	if f.RuleID != "" {
		where = append(where, "rule_id = "+arg(f.RuleID))
	}
	if f.Query != "" {
		where = append(where, "(lower(title) like '%'||lower("+arg(f.Query)+")||'%' or src_ip like '%'||"+arg(f.Query)+"||'%')")
	}
	if f.Limit <= 0 {
		f.Limit = 50
	}
	q := `select * from sentinel_alerts where ` + strings.Join(where, " and ") +
		` order by (status <> 'RESOLVED') desc, severity desc, last_seen_at desc limit ` + arg(f.Limit) + ` offset ` + arg(f.Offset)
	rows, err := p.pool.Query(context.Background(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*alerts.Alert{}
	for rows.Next() {
		a, err := p.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *PostgresStore) FindOpen(ruleID, ruleKey string) (*alerts.Alert, error) {
	row, err := p.pool.Query(context.Background(),
		`select * from sentinel_alerts where rule_id=$1 and rule_key=$2 and status <> 'RESOLVED' order by last_seen_at desc limit 1`,
		ruleID, ruleKey)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	if !row.Next() {
		return nil, alerts.ErrNotFound
	}
	return p.scan(row)
}

func (p *PostgresStore) Counts() (alerts.Counts, error) {
	c := alerts.Counts{BySeverity: map[event.Severity]int{}}
	rows, err := p.pool.Query(context.Background(), `
		select severity, status,
		       count(*) filter (where status <> 'RESOLVED') as active,
		       count(*) filter (where status = 'RESOLVED') as resolved,
		       count(*) filter (where status = 'OPEN' and assignee = '') as unassigned
		from sentinel_alerts group by severity, status`)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev, status string
		var active, resolved, unassigned int
		if err := rows.Scan(&sev, &status, &active, &resolved, &unassigned); err != nil {
			return c, err
		}
		s := event.Severity(sev)
		c.BySeverity[s] += active + resolved
		switch s {
		case event.SeverityCritical:
			c.Critical += active + resolved
		case event.SeverityHigh:
			c.High += active + resolved
		case event.SeverityMedium:
			c.Medium += active + resolved
		case event.SeverityLow:
			c.Low += active + resolved
		}
		c.TotalActive += active
		c.Resolved += resolved
		c.Unassigned += unassigned
		switch alerts.Status(status) {
		case alerts.StatusOpen:
			c.Open += active
		case alerts.StatusAssigned:
			c.Assigned += active
		case alerts.StatusInProgress:
			c.InProgress += active
		}
	}
	return c, nil
}

func (p *PostgresStore) MTTR() (time.Duration, int, error) {
	var secs float64
	var n int
	err := p.pool.QueryRow(context.Background(), `
		select coalesce(avg(extract(epoch from (coalesce(responded_at, resolved_at) - created_at))), 0)::float8,
		       count(*) filter (where responded_at is not null or resolved_at is not null)
		from sentinel_alerts`).Scan(&secs, &n)
	if err != nil {
		return 0, 0, err
	}
	if n == 0 {
		return 0, 0, nil
	}
	return time.Duration(secs) * time.Second, n, nil
}
