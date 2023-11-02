package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var threatDBFile = "threats.db"
var useIntel = false
var intelDir = "intel"
var feedName = "feed_config.json"

type Feeds struct {
	Feeds []Feed `json:"feeds"`
}
type Feed struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"`
}
type threatsCatReport struct {
	category string
	count    int
}

func summarizeThreatDB(logger zerolog.Logger) {
	db, err := openDBConnection(logger)
	logger.Info().Msg("Summarized ThreatDB Info")
	if err != nil {
		logger.Error().Msg("Could not initialize access to threat DB!")
		return
	}
	query := "SELECT COUNT(*) as c FROM ips"
	rows, err := db.Query(query)
	if err != nil {
		return
	}
	var ipCount string
	for rows.Next() {
		err = rows.Scan(&ipCount)
	}
	rows.Close()
	logger.Info().Msgf("Total Unique IPs: %v", ipCount)

	query_types := "SELECT category, COUNT(*) as count FROM ips GROUP BY category"
	rows_types, err := db.Query(query_types)
	if err != nil {
		return
	}
	for rows_types.Next() {
		tmp := threatsCatReport{}
		if err := rows_types.Scan(&tmp.category, &tmp.count); err != nil {
			return
		}
		logger.Info().Msgf("Category %v: %v", tmp.category, tmp.count)
	}
}

func buildThreatDB(arguments map[string]any, logger zerolog.Logger) error {
	// First check if the db exists - if not, initialize the database
	// Table name: ips
	// Columns (all string): ip, url, type
	// type values: proxy, suspicious, tor
	_, err := os.Stat(threatDBFile)
	if errors.Is(err, os.ErrNotExist) {
		initErrr := initializeThreatDB(logger)
		if initErrr != nil {
			return initErrr
		}
	}
	// If we are updating intel, lets do so now.
	// Read our feed file first to use both in intel downloads then in pushing to the sqlite
	var feeds Feeds
	jsonData, ReadErr := os.ReadFile(feedName)
	if ReadErr != nil {
		logger.Error().Msg(ReadErr.Error())
		return ReadErr
	}

	jsonErr := json.Unmarshal(jsonData, &feeds)
	if jsonErr != nil {
		logger.Error().Msg(jsonErr.Error())
		return jsonErr
	}

	if arguments["updateti"].(bool) {
		UpdateErr := updateIntelligence(logger, feeds)
		if UpdateErr != nil {
			return UpdateErr
		}
	}

	// Now we have downloaded intel to intelDir - lets go through each file and parse for ipAddress hits within each file - we will use the filename to tell us what 'type' the data should be categorized as
	ingestErr := ingestIntel(logger, feeds)
	if ingestErr != nil {
		return ingestErr
	}

	useIntel = true
	return nil
}

func updateIntelligence(logger zerolog.Logger, feeds Feeds) error {
	// Iterate through feeds and downloads each file as $FEEDNAME_TIMESTAMP.txt into newly created 'intel' directory if it does not exist
	if err := os.Mkdir(intelDir, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		logger.Error().Msg(err.Error())
		return err
	}
	//t := time.Now().Format("20060102150405")
	var waiter WaitGroupCount
	for i := 0; i < len(feeds.Feeds); i++ {
		i := i
		go func() {
			waiter.Add(1)
			defer waiter.Done()
			destFile := fmt.Sprintf("%v\\%v.txt", intelDir, feeds.Feeds[i].Name)
			Derr := downloadFile(logger, feeds.Feeds[i].URL, destFile, "")
			if Derr != nil {
				logger.Error().Msgf("Error Getting File from %v: %v ", feeds.Feeds[i].URL, Derr.Error())
			}
		}()
	}
	time.Sleep(1 * time.Second)
	logger.Info().Msg("Waiting for Intelligence Downloads...")
	waiter.Wait()
	return nil
}

func initializeThreatDB(logger zerolog.Logger) error {
	file, CreateErr := os.Create(threatDBFile) // Create SQLite file
	if CreateErr != nil {
		logger.Error().Msg(CreateErr.Error())
		return CreateErr
	}
	file.Close()
	db, _ := sql.Open("sqlite3", threatDBFile)
	defer db.Close()
	createTableStatement := `CREATE TABLE ips ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "ip" TEXT, "category" TEXT, UNIQUE(ip));`
	_, exeE := db.Exec(createTableStatement)
	if exeE != nil {
		logger.Error().Msg(CreateErr.Error())
		return exeE
	}
	return nil
}

func openDBConnection(logger zerolog.Logger) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", threatDBFile)
	return db, err
}

func ingestIntel(logger zerolog.Logger, feeds Feeds) error {
	logger.Info().Msg("Ingesting Intelligence Feeds...")
	typeMap := make(map[string]string)
	urlMap := make(map[string]string)
	db, err := openDBConnection(logger)
	if err != nil {
		return err
	}
	for i := 0; i < len(feeds.Feeds); i++ {
		typeMap[feeds.Feeds[i].Name] = feeds.Feeds[i].Type
		urlMap[feeds.Feeds[i].Name] = feeds.Feeds[i].URL
	}
	intelFiles, err := os.ReadDir(intelDir)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	for _, e := range intelFiles {
		baseNameWithoutExtension := strings.TrimSuffix(filepath.Base(e.Name()), filepath.Ext(e.Name()))
		err = ingestFile(fmt.Sprintf("%v\\%v", intelDir, e.Name()), typeMap[baseNameWithoutExtension], urlMap[baseNameWithoutExtension], db, logger)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
	}

	return nil
}

func ingestFile(inputFile string, iptype string, url string, db *sql.DB, logger zerolog.Logger) error {
	logger.Info().Msgf("Ingesting %v", inputFile)
	fileLines := ReadFileToSlice(inputFile, logger)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("insert or ignore into ips(ip, category) values(?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, line := range fileLines {
		lineTrimmed := strings.TrimSpace(line)
		if strings.HasPrefix(lineTrimmed, "#") {
			continue
		}
		v, e := regexFirstPublicIPFromString(lineTrimmed)
		if e {
			_, err = stmt.Exec(v, iptype)
			if err != nil {
				return err
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func CheckIPinTI(ip string, db *sql.DB) (string, bool, error) {
	query := fmt.Sprintf("select category from ips where ip = \"%v\"", ip)
	/*	stmt, err := db.Prepare(query)
		if err != nil {
			return "", false
		}
		defer stmt.Close()
		r, err := stmt.Exec()
		if err != nil {
			return "", false
		}*/
	rows, err := db.Query(query)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var iptype string
		err = rows.Scan(&iptype)
		if err != nil {
			return "", false, err
		}
		return iptype, true, nil
	}
	err = rows.Err()
	if err != nil {
		return "", false, err
	}

	return "", false, err
}

func CheckTor(ip string) bool {
	torCheckMut.RLock()
	defer torCheckMut.RUnlock()
	_, e := torNodeMap[ip]
	return e
}
