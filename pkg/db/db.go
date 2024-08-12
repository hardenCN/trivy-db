package db

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/hardenCN/trivy-db/pkg/log"
	"github.com/hardenCN/trivy-db/pkg/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

type CustomPut func(dbc Operation, tx *bolt.Tx, adv interface{}) error

const SchemaVersion = 2

var db *bolt.DB
var sqlDb *sql.DB

type Operation interface {
	BatchUpdate(fn func(*bolt.Tx) error) (err error)

	GetVulnerabilityDetail(cveID string) (detail map[types.SourceID]types.VulnerabilityDetail, err error)
	PutVulnerabilityDetail(tx *bolt.Tx, vulnerabilityID string, source types.SourceID,
		vulnerability types.VulnerabilityDetail) (err error)
	DeleteVulnerabilityDetailBucket() (err error)

	ForEachAdvisory(sources []string, pkgName string) (value map[string]Value, err error)
	GetAdvisories(source string, pkgName string) (advisories []types.Advisory, err error)

	PutVulnerabilityID(tx *bolt.Tx, vulnerabilityID string) (err error)
	ForEachVulnerabilityID(fn func(tx *bolt.Tx, cveID string) error) (err error)

	PutVulnerability(tx *bolt.Tx, vulnerabilityID string, vulnerability types.Vulnerability) (err error)
	GetVulnerability(vulnerabilityID string) (vulnerability types.Vulnerability, err error)

	SaveAdvisoryDetails(tx *bolt.Tx, cveID string) (err error)
	PutAdvisoryDetail(tx *bolt.Tx, vulnerabilityID, pkgName string, nestedBktNames []string, advisory interface{}) (err error)
	DeleteAdvisoryDetailBucket() error

	PutDataSource(tx *bolt.Tx, bktName string, source types.DataSource) (err error)

	// For Red Hat
	PutRedHatRepositories(tx *bolt.Tx, repository string, cpeIndices []int) (err error)
	PutRedHatNVRs(tx *bolt.Tx, nvr string, cpeIndices []int) (err error)
	PutRedHatCPEs(tx *bolt.Tx, cpeIndex int, cpe string) (err error)
	RedHatRepoToCPEs(repository string) (cpeIndices []int, err error)
	RedHatNVRToCPEs(nvr string) (cpeIndices []int, err error)
}

type Config struct {
}

func Init(dbDir string) (err error) {
	if err = os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}
	dbPath := Path(dbDir)

	// bbolt sometimes occurs the fatal error of "unexpected fault address".
	// In that case, the local DB should be broken and needs to be removed.
	debug.SetPanicOnFault(true)
	defer func() {
		if r := recover(); r != nil {
			if err = os.Remove(dbPath); err != nil {
				return
			}
			db, err = bolt.Open(dbPath, 0600, nil)
		}
		debug.SetPanicOnFault(false)
	}()

	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return xerrors.Errorf("failed to open db: %w", err)
	}
	return nil
}

func InitDB(dbType, dsn, dbDir string) (err error) {
	if len(dbType) > 0 && dbType != "sqlite" {
		err = Init(dbDir)
		if err != nil {
			return xerrors.Errorf("failed to open db: %w", err)
		}
		sqlDb, err = dbOpen(dbType, dsn)
		if err != nil {
			return xerrors.Errorf("failed to open sql db: %w", err)
		}
		return nil
	} else {
		return Init(dbDir)
	}
}

func dbOpen(dbType, dsn string) (*sql.DB, error) {
	var sqldb *sql.DB
	var err error
	switch dbType {
	case "mysql":
		sqldb, err = sql.Open("mysql", dsn)
	case "postgres", "postgresql", "pg":
		pgconfig, cfgErr := pgxpool.ParseConfig(dsn)
		if cfgErr != nil {
			err = xerrors.Errorf("failed to parse db config: %w", cfgErr)
		}
		sqldb = stdlib.OpenDB(*pgconfig.ConnConfig)
	default:
		sqldb, err = sql.Open("sqlite", dsn)
	}
	if err != nil {
		return nil, xerrors.Errorf("can't open db: %w", err)
	}
	sqldb.SetMaxOpenConns(30)
	sqldb.SetMaxIdleConns(10)
	return sqldb, nil
}

func Path(dbDir string) string {
	dbPath := filepath.Join(dbDir, "trivy.db")
	return dbPath
}

func Close() error {
	// Skip closing the database if the connection is not established.
	if db == nil && sqlDb == nil {
		return nil
	}
	if db != nil {
		if err := db.Close(); err != nil {
			return xerrors.Errorf("failed to close DB: %w", err)
		}
	}
	if sqlDb != nil {
		if err := sqlDb.Close(); err != nil {
			return xerrors.Errorf("failed to close sqlDB: %w", err)
		}
	}
	return nil
}

func (dbc Config) Connection() *bolt.DB {
	return db
}

func (dbc Config) BatchUpdate(fn func(tx *bolt.Tx) error) error {
	err := db.Batch(fn)
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (dbc Config) put(tx *bolt.Tx, bktNames []string, key string, value interface{}) error {
	if len(bktNames) == 0 {
		return xerrors.Errorf("empty bucket name")
	}

	bkt, err := tx.CreateBucketIfNotExists([]byte(bktNames[0]))
	if err != nil {
		return xerrors.Errorf("failed to create '%s' bucket: %w", bktNames[0], err)
	}

	for _, bktName := range bktNames[1:] {
		bkt, err = bkt.CreateBucketIfNotExists([]byte(bktName))
		if err != nil {
			return xerrors.Errorf("failed to create a bucket: %w", err)
		}
	}
	v, err := json.Marshal(value)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal JSON: %w", err)
	}

	return bkt.Put([]byte(key), v)
}

func (dbc Config) get(bktNames []string, key string) (value []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		if len(bktNames) == 0 {
			return xerrors.Errorf("empty bucket name")
		}

		bkt := tx.Bucket([]byte(bktNames[0]))
		if bkt == nil {
			return nil
		}
		for _, bktName := range bktNames[1:] {
			bkt = bkt.Bucket([]byte(bktName))
			if bkt == nil {
				return nil
			}
		}
		dbValue := bkt.Get([]byte(key))

		// Copy the byte slice so it can be used outside of the current transaction
		value = make([]byte, len(dbValue))
		copy(value, dbValue)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get data from db: %w", err)
	}
	return value, nil
}

type Value struct {
	Source  types.DataSource
	Content []byte
}

func driverName(sqldb *sql.DB) string {
	driver := sqldb.Driver()
	a := reflect.TypeOf(driver)
	return a.String()
}

func (dbc Config) forEach(bktNames []string) (map[string]Value, error) {
	isSql := sqlDb != nil
	if isSql {
		// 使用mysql或pg
		dn := driverName(sqlDb)
		if len(bktNames) < 2 {
			return nil, xerrors.Errorf("bucket must be nested: %v", bktNames)
		}
		rootBucket, nestedBuckets := bktNames[0], bktNames[1:]
		values := map[string]Value{}
		dsMap := map[string]types.DataSource{}
		db.View(func(tx *bolt.Tx) error {
			var rootBuckets []string
			if strings.Contains(rootBucket, "::") {
				// e.g. "pip::", "rubygems::"
				prefix := []byte(rootBucket)
				c := tx.Cursor()
				for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
					rootBuckets = append(rootBuckets, string(k))
				}
			} else {
				// e.g. "GitHub Security Advisory Composer"
				rootBuckets = append(rootBuckets, rootBucket)
			}
			for _, r := range rootBuckets {
				root := tx.Bucket([]byte(r))
				if root == nil {
					continue
				}
				source, err := dbc.getDataSource(tx, r)
				if err != nil {
					log.Logger.Debugf("Data source error: %s", err)
				}
				dsMap[r] = source
			}
			return nil
		})
		querySql := `
					SELECT v.vulnerability_id, v.platform, v.segment, v.package, v.value
					FROM vulnerability_advisories v 
					WHERE v.platform %s %s AND v.package in (%s)`
		var platform string
		var platformOperator string
		var inClauseStr string
		if strings.Contains(rootBucket, "::") {
			platformOperator = "like"
			// e.g. "pip::", "rubygems::"
			platform = "'" + rootBucket + "%'"
		} else {
			platformOperator = "="
			// e.g. "GitHub Security Advisory Composer"
			platform = "'" + rootBucket + "'"
		}
		switch dn {
		case "*stdlib.Driver":
			// 动态构建 IN 子句
			var inClause strings.Builder
			for i := range nestedBuckets {
				inClause.WriteString(fmt.Sprintf("$%d,", i+1))
			}
			inClauseStr = inClause.String()
			inClauseStr = inClauseStr[:len(inClauseStr)-1] // 去掉最后一个逗号
		default:
			// 动态构建 IN 子句
			inClauseStr = strings.Repeat("?,", len(nestedBuckets))
			inClauseStr = inClauseStr[:len(inClauseStr)-1] // 去掉最后一个逗号
		}
		querySql = fmt.Sprintf(querySql, platformOperator, platform, inClauseStr)
		// 转换参数为 interface{} 切片
		args := make([]interface{}, len(nestedBuckets))
		for i, pkg := range nestedBuckets {
			args[i] = pkg
		}
		// 执行查询
		rows, err := sqlDb.Query(querySql, args...)
		if err != nil {
			return nil, xerrors.Errorf("failed to exe sqlDb query: %w", err)
		}
		defer rows.Close()
		// 遍历结果
		for rows.Next() {
			var vulnerabilityId, platformValue, segmentValue, pkgValue string
			var value []byte
			if err := rows.Scan(&vulnerabilityId, &platformValue, &segmentValue, &pkgValue, &value); err != nil {
				return nil, xerrors.Errorf("failed to loop sqldb rows: %w", err)
			}
			var dsKey string
			if len(segmentValue) > 0 {
				dsKey = platformValue + " " + segmentValue
			} else {
				dsKey = platformValue
			}
			values[vulnerabilityId] = Value{
				Source:  dsMap[dsKey],
				Content: value,
			}
		}
		// 检查遍历中的错误
		if err = rows.Err(); err != nil {
			return nil, xerrors.Errorf("failed to loop sqldb rows: %w", err)
		}
		return values, nil
	} else {
		if len(bktNames) < 2 {
			return nil, xerrors.Errorf("bucket must be nested: %v", bktNames)
		}
		rootBucket, nestedBuckets := bktNames[0], bktNames[1:]

		values := map[string]Value{}
		err := db.View(func(tx *bolt.Tx) error {
			var rootBuckets []string

			if strings.Contains(rootBucket, "::") {
				// e.g. "pip::", "rubygems::"
				prefix := []byte(rootBucket)
				c := tx.Cursor()
				for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
					rootBuckets = append(rootBuckets, string(k))
				}
			} else {
				// e.g. "GitHub Security Advisory Composer"
				rootBuckets = append(rootBuckets, rootBucket)
			}

			for _, r := range rootBuckets {
				root := tx.Bucket([]byte(r))
				if root == nil {
					continue
				}

				source, err := dbc.getDataSource(tx, r)
				if err != nil {
					log.Logger.Debugf("Data source error: %s", err)
				}

				bkt := root
				for _, nestedBkt := range nestedBuckets {
					bkt = bkt.Bucket([]byte(nestedBkt))
					if bkt == nil {
						break
					}
				}
				if bkt == nil {
					continue
				}

				err = bkt.ForEach(func(k, v []byte) error {
					if len(v) == 0 {
						return nil
					}
					// Copy the byte slice so it can be used outside of the current transaction
					copiedContent := make([]byte, len(v))
					copy(copiedContent, v)

					values[string(k)] = Value{
						Source:  source,
						Content: copiedContent,
					}
					return nil
				})
				if err != nil {
					return xerrors.Errorf("db foreach error: %w", err)
				}
			}
			return nil
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get all key/value in the specified bucket: %w", err)
		}
		return values, nil
	}
}

func (dbc Config) deleteBucket(bucketName string) error {
	return db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(bucketName)); err != nil {
			return xerrors.Errorf("failed to delete bucket: %w", err)
		}
		return nil
	})
}
