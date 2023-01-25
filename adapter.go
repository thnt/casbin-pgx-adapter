package pgxadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeebo/xxh3"
)

const DefaultTableName = "casbin_rules"
const DefaultDatabaseName = "casbin"

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	ID    string
	Ptype string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

type Filter struct {
	P []string
	G []string
}

// Adapter represents the adapter for policy storage.
type Adapter struct {
	db              *pgxpool.Pool
	tableName       string
	skipTableCreate bool
	filtered        bool
}

type Option func(a *Adapter)

// NewAdapter is the constructor for Adapter.
// param:arg should be a PostgreS URL string or of type *pgxpool.Config
// param:dbname is the name of the database to use and can is optional.
// If no dbname is provided, the default database name is "casbin" which will be created automatically.
// If arg is *pgxpool.Config, the arg.ConnConfig.Database field is omitted and will be modified according to dbname
func NewAdapter(arg any, dbname ...string) (*Adapter, error) {
	dbn := DefaultDatabaseName
	if len(dbname) > 0 {
		dbn = dbname[0]
	}
	db, err := createCasbinDatabase(arg, dbn)

	if err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	a := &Adapter{db: db, tableName: DefaultTableName}

	if err := a.createTableifNotExists(); err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	return a, nil
}

// NewAdapterByDB creates new Adapter by using existing DB connection
// creates table from CasbinRule struct if it doesn't exist
func NewAdapterByDB(db *pgxpool.Pool, opts ...Option) (*Adapter, error) {
	a := &Adapter{db: db, tableName: DefaultTableName}
	for _, opt := range opts {
		opt(a)
	}

	if !a.skipTableCreate {
		if err := a.createTableifNotExists(); err != nil {
			return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
		}
	}
	return a, nil
}

// WithTableName can be used to pass custom table name for Casbin rules
func WithTableName(tableName string) Option {
	return func(a *Adapter) {
		a.tableName = tableName
	}
}

// SkipTableCreate skips the table creation step when the adapter starts
// If the Casbin rules table does not exist, it will lead to issues when using the adapter
func SkipTableCreate() Option {
	return func(a *Adapter) {
		a.skipTableCreate = true
	}
}

func createCasbinDatabase(arg any, dbname string) (*pgxpool.Pool, error) {
	var err error
	var pool *pgxpool.Pool
	var cfg *pgxpool.Config
	ctx := context.Background()
	if connURL, ok := arg.(string); ok {
		cfg, err = pgxpool.ParseConfig(connURL)
	} else {
		cfg, ok = arg.(*pgxpool.Config)
		if !ok {
			return nil, fmt.Errorf("must pass in a PostgreS URL string or an instance of *pgxpool.Config, received %T instead", arg)
		}
	}
	if err != nil {
		return nil, err
	}
	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	defer pool.Close()

	_, err = pool.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", dbname))
	if err != nil && !strings.Contains(err.Error(), "42P04") {
		return nil, err
	}
	pool.Close()

	cfg.ConnConfig.Database = dbname
	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return pool, nil
}

// Close close database connection
func (a *Adapter) Close() error {
	if a != nil && a.db != nil {
		a.db.Close()
	}
	return nil
}

func (a *Adapter) createTableifNotExists() error {
	_, err := a.db.Exec(context.Background(), fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS "%v" (
			id TEXT PRIMARY KEY,
			ptype TEXT NOT NULL,
			v0 TEXT,
			v1 TEXT,
			v2 TEXT,
			v3 TEXT,
			v4 TEXT,
			v5 TEXT
		)
	`, a.tableName))
	if err != nil {
		return err
	}
	return nil
}

func (r *CasbinRule) String() string {
	const prefixLine = ", "
	var sb strings.Builder

	sb.Grow(
		len(r.Ptype) +
			len(r.V0) + len(r.V1) + len(r.V2) +
			len(r.V3) + len(r.V4) + len(r.V5),
	)

	sb.WriteString(r.Ptype)
	if len(r.V0) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V0)
	}
	if len(r.V1) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V1)
	}
	if len(r.V2) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V2)
	}
	if len(r.V3) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V3)
	}
	if len(r.V4) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V4)
	}
	if len(r.V5) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V5)
	}

	return sb.String()
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []*CasbinRule
	ctx := context.Background()
	rows, err := a.db.Query(ctx, fmt.Sprintf(`SELECT * FROM "%v"`, a.tableName))
	if err != nil {
		return err
	}

	for rows.Next() {
		var id, ptype, v0, v1, v2, v3, v4, v5 string
		if err := rows.Scan(&id, &ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
			return err
		}
		lines = append(lines, &CasbinRule{
			ID:    id,
			Ptype: ptype,
			V0:    v0,
			V1:    v1,
			V2:    v2,
			V3:    v3,
			V4:    v4,
			V5:    v5,
		})
	}
	rows.Close()

	for _, line := range lines {
		err := persist.LoadPolicyLine(line.String(), model)
		if err != nil {
			return err
		}
	}

	a.filtered = false

	return nil
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := xxh3.HashString(data)
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{Ptype: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	line.ID = policyID(ptype, rule)

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("start DB transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, fmt.Sprintf(`DELETE FROM "%v"`, a.tableName))
	if err != nil {
		return err
	}

	var lines []*CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		_, err = tx.Exec(ctx,
			fmt.Sprintf(`INSERT INTO "%v" VALUES($1, $2, $3, $4, $5, $6, $7, $8)`, a.tableName),
			line.ID, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		fmt.Sprintf(`INSERT INTO "%v" VALUES($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`, a.tableName),
		line.ID, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5,
	)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		_, err = tx.Exec(ctx,
			fmt.Sprintf(`INSERT INTO "%v" VALUES($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`, a.tableName),
			line.ID, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		fmt.Sprintf(`DELETE FROM "%v" WHERE id=$1`, a.tableName),
		line.ID,
	)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		_, err = tx.Exec(ctx,
			fmt.Sprintf(`DELETE FROM "%v" WHERE id=$1`, a.tableName),
			line.ID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	sql := fmt.Sprintf(`DELETE FROM "%v" WHERE ptype = $1`, a.tableName)
	args := []any{ptype}

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 && fieldValues[0-fieldIndex] != "" {
		sql += fmt.Sprintf(" AND v0 = $%v", len(args)+1)
		args = append(args, fieldValues[0-fieldIndex])
	}
	if fieldIndex <= 1 && idx > 1 && fieldValues[1-fieldIndex] != "" {
		sql += fmt.Sprintf(" AND v1 = $%v", len(args)+1)
		args = append(args, fieldValues[1-fieldIndex])
	}
	if fieldIndex <= 2 && idx > 2 && fieldValues[2-fieldIndex] != "" {
		sql += fmt.Sprintf(" AND v2 = $%v", len(args)+1)
		args = append(args, fieldValues[2-fieldIndex])
	}
	if fieldIndex <= 3 && idx > 3 && fieldValues[3-fieldIndex] != "" {
		sql += fmt.Sprintf(" AND v3 = $%v", len(args)+1)
		args = append(args, fieldValues[3-fieldIndex])
	}
	if fieldIndex <= 4 && idx > 4 && fieldValues[4-fieldIndex] != "" {
		sql += fmt.Sprintf(" AND v4 = $%v", len(args)+1)
		args = append(args, fieldValues[4-fieldIndex])
	}
	if fieldIndex <= 5 && idx > 5 && fieldValues[5-fieldIndex] != "" {
		sql += fmt.Sprintf(" AND v5 = $%v", len(args)+1)
		args = append(args, fieldValues[5-fieldIndex])
	}

	_, err = tx.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (a *Adapter) LoadFilteredPolicy(model model.Model, filter any) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("invalid filter type")
	}
	err := a.loadFilteredPolicy(model, filterValue, persist.LoadPolicyLine)
	if err != nil {
		return err
	}
	a.filtered = true
	return nil
}

func buildQuery(query string, args []any, values []string) (string, []any, error) {
	for ind, v := range values {
		if v == "" {
			continue
		}
		switch ind {
		case 0:
			query += fmt.Sprintf(" AND v0 = $%v", len(args)+1)
			args = append(args, v)
		case 1:
			query += fmt.Sprintf(" AND v1 = $%v", len(args)+1)
			args = append(args, v)
		case 2:
			query += fmt.Sprintf(" AND v2 = $%v", len(args)+1)
			args = append(args, v)
		case 3:
			query += fmt.Sprintf(" AND v3 = $%v", len(args)+1)
			args = append(args, v)
		case 4:
			query += fmt.Sprintf(" AND v4 = $%v", len(args)+1)
			args = append(args, v)
		case 5:
			query += fmt.Sprintf(" AND v5 = $%v", len(args)+1)
			args = append(args, v)
		default:
			return "", nil, fmt.Errorf("filter has more values than expected, should not exceed 6 values")
		}
	}

	return query, args, nil
}

func (a *Adapter) loadFilteredPolicy(model model.Model, filter *Filter, handler func(string, model.Model) error) error {
	ctx := context.Background()
	sql := fmt.Sprintf(`SELECT * FROM "%v" WHERE ptype=$1`, a.tableName)
	if filter.P != nil {
		lines := []*CasbinRule{}
		args := []any{"p"}
		sql, args, err := buildQuery(sql, args, filter.P)
		if err != nil {
			return err
		}
		rows, err := a.db.Query(ctx, sql, args...)
		if err != nil {
			return err
		}

		for rows.Next() {
			var id, ptype, v0, v1, v2, v3, v4, v5 string
			if err := rows.Scan(&id, &ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
				return err
			}
			lines = append(lines, &CasbinRule{
				ID:    id,
				Ptype: ptype,
				V0:    v0,
				V1:    v1,
				V2:    v2,
				V3:    v3,
				V4:    v4,
				V5:    v5,
			})
		}
		rows.Close()

		for _, line := range lines {
			handler(line.String(), model)
		}
	}
	if filter.G != nil {
		lines := []*CasbinRule{}
		args := []any{"g"}
		sql, args, err := buildQuery(sql, args, filter.G)
		if err != nil {
			return err
		}
		rows, err := a.db.Query(ctx, sql, args...)
		if err != nil {
			return err
		}

		for rows.Next() {
			var id, ptype, v0, v1, v2, v3, v4, v5 string
			if err := rows.Scan(&id, &ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
				return err
			}
			lines = append(lines, &CasbinRule{
				ID:    id,
				Ptype: ptype,
				V0:    v0,
				V1:    v1,
				V2:    v2,
				V3:    v3,
				V4:    v4,
				V5:    v5,
			})
		}
		rows.Close()

		for _, line := range lines {
			handler(line.String(), model)
		}
	}

	return nil
}

func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newPolicy})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	oldLines := make([]*CasbinRule, 0, len(oldRules))
	newLines := make([]*CasbinRule, 0, len(newRules))
	for _, rule := range oldRules {
		oldLines = append(oldLines, savePolicyLine(ptype, rule))
	}
	for _, rule := range newRules {
		newLines = append(newLines, savePolicyLine(ptype, rule))
	}

	return a.updatePolicies(oldLines, newLines)
}

func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	line := &CasbinRule{}

	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]CasbinRule, 0, len(newPolicies))
	oldP := make([]CasbinRule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, *(savePolicyLine(ptype, newRule)))
	}

	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	for i := range newP {
		str, args := line.queryString()

		sql := fmt.Sprintf(`DELETE FROM "%v" WHERE %v`, a.tableName, str)
		_, err = tx.Exec(ctx, sql, args...)
		if err != nil {
			return nil, err
		}

		row := newP[i]
		_, err = tx.Exec(ctx, fmt.Sprintf(
			`INSERT INTO "%v" VALUES($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`,
			a.tableName,
		), row.ID, row.Ptype, row.V0, row.V1, row.V2, row.V3, row.V4, row.V5)

		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, err
}

func (c *CasbinRule) queryString() (string, []any) {
	queryArgs := []any{c.Ptype}

	queryStr := "ptype = $1"
	if c.V0 != "" {
		queryStr += fmt.Sprintf(" AND v0 = $%v", len(queryArgs)+1)
		queryArgs = append(queryArgs, c.V0)
	}
	if c.V1 != "" {
		queryStr += fmt.Sprintf(" AND v1 = $%v", len(queryArgs)+1)
		queryArgs = append(queryArgs, c.V1)
	}
	if c.V2 != "" {
		queryStr += fmt.Sprintf(" AND v2 = $%v", len(queryArgs)+1)
		queryArgs = append(queryArgs, c.V2)
	}
	if c.V3 != "" {
		queryStr += fmt.Sprintf(" AND v3 = $%v", len(queryArgs)+1)
		queryArgs = append(queryArgs, c.V3)
	}
	if c.V4 != "" {
		queryStr += fmt.Sprintf(" AND v4 = $%v", len(queryArgs)+1)
		queryArgs = append(queryArgs, c.V4)
	}
	if c.V5 != "" {
		queryStr += fmt.Sprintf(" AND v5 = $%v", len(queryArgs)+1)
		queryArgs = append(queryArgs, c.V5)
	}

	return queryStr, queryArgs
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.Ptype != "" {
		policy = append(policy, c.Ptype)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	return policy
}

func (a *Adapter) updatePolicies(oldLines, newLines []*CasbinRule) error {
	ctx := context.Background()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for i, line := range oldLines {
		str, args := line.queryString()

		sql := fmt.Sprintf(
			`UPDATE "%v" SET ptype=$%v, v0=$%v, v1=$%v, v2=$%v, v3=$%v, v4=$%v, v5=$%v WHERE %v`,
			a.tableName,
			len(args)+1,
			len(args)+2,
			len(args)+3,
			len(args)+4,
			len(args)+5,
			len(args)+6,
			len(args)+7,
			str,
		)
		row := newLines[i]
		args = append(args, row.Ptype, row.V0, row.V1, row.V2, row.V3, row.V4, row.V5)
		_, err = tx.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}
