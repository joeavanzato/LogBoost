package helpers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/joeavanzato/logboost/lbtypes"
	"github.com/rs/zerolog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ThreatDBFile = "threats.db"
var UseIntel = false
var intelDir = "intel"
var feedName = "feed_config.json"

type Feeds struct {
	Feeds []Feed `json:"feeds"`
}
type Feed struct {
	Name string   `json:"name"`
	URL  string   `json:"url"`
	Type []string `json:"type"`
}
type threatsCatReport struct {
	category string
	count    int
}

type iPCheckResults struct {
	feed_name string
	category  string
}

var CategoryMap = make(map[string]int) // Maps Intel Category string to corresponding RowID in DB

func SummarizeThreatDB(logger zerolog.Logger) {
	db, err := OpenDBConnection(logger)
	logger.Info().Msg("Summarizing ThreatDB Info")
	if err != nil {
		logger.Error().Msg("Could not initialize access to threat DB!")
		return
	}
	query := "SELECT COUNT(DISTINCT(ip)) as c FROM ips"
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

	query_types := "SELECT categories.category_value, COUNT(*) as count FROM ips INNER JOIN categories ON ips.category = categories.category_id GROUP BY category"
	rows_types, err := db.Query(query_types)
	if err != nil {
		return
	}
	for rows_types.Next() {
		tmp := threatsCatReport{}
		if err := rows_types.Scan(&tmp.category, &tmp.count); err != nil {
			return
		}
		logger.Info().Msgf("%v: %v", tmp.category, tmp.count)
	}
}

func BuildThreatDB(arguments map[string]any, logger zerolog.Logger) error {
	// First check if the db exists - if not, initialize the database
	// Table name: ips
	// Columns (all string): ip, url, type
	// type values: proxy, suspicious, tor
	_, err := os.Stat(ThreatDBFile)
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

	UpdateErr := updateIntelligence(logger, feeds)
	if UpdateErr != nil {
		return UpdateErr
	}
	// Now we have downloaded intel to intelDir - lets go through each file and parse for ipAddress hits within each file - we will use the filename to tell us what 'type' the data should be categorized as
	ingestErr := ingestIntel(logger, feeds)
	if ingestErr != nil {
		return ingestErr
	}

	UseIntel = true
	return nil
}

func updateIntelligence(logger zerolog.Logger, feeds Feeds) error {
	// Iterate through feeds and downloads each file as $FEEDNAME.txt into newly created 'intel' directory if it does not exist
	if err := os.Mkdir(intelDir, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		logger.Error().Msg(err.Error())
		return err
	}
	//t := time.Now().Format("20060102150405")
	var waiter lbtypes.WaitGroupCount
	for i := 0; i < len(feeds.Feeds); i++ {
		i := i
		go func() {
			waiter.Add(1)
			defer waiter.Done()
			destFile := fmt.Sprintf("%v\\%v.txt", intelDir, feeds.Feeds[i].Name)
			Derr := DownloadFile(logger, feeds.Feeds[i].URL, destFile, "")
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
	file, CreateErr := os.Create(ThreatDBFile) // Create SQLite file
	if CreateErr != nil {
		logger.Error().Msg(CreateErr.Error())
		return CreateErr
	}
	file.Close()
	db, _ := sql.Open("sqlite3", ThreatDBFile)
	defer db.Close()
	//createIOCTable := `CREATE TABLE ips ("ip" TEXT PRIMARY KEY, "category" TEXT, "feed_count" INT, ids TEXT, UNIQUE(ip)) WITHOUT ROWID;`
	createIOCTable := `CREATE TABLE ips ("ip" TEXT, "feed" INTEGER, "category" INTEGER, UNIQUE(ip, feed, category));`
	err := createDBTable(logger, createIOCTable, db)
	if err != nil {
		return err
	}
	createFeedTable := `CREATE TABLE feeds ("feed_id" INTEGER PRIMARY KEY, "feed_url" TEXT,"feed_name" TEXT, UNIQUE(feed_name));`
	err = createDBTable(logger, createFeedTable, db)
	if err != nil {
		return err
	}
	createCategoryTable := `CREATE TABLE categories ("category_id" INTEGER PRIMARY KEY, "category_value" TEXT, UNIQUE(category_value));`
	err = createDBTable(logger, createCategoryTable, db)
	if err != nil {
		return err
	}
	return nil
}

func createDBTable(logger zerolog.Logger, statement string, db *sql.DB) error {
	_, exeE := db.Exec(statement)
	if exeE != nil {
		logger.Error().Msg(exeE.Error())
		return exeE
	}
	return nil
}

func OpenDBConnection(logger zerolog.Logger) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ThreatDBFile)
	return db, err
}

func ingestIntel(logger zerolog.Logger, feeds Feeds) error {
	logger.Info().Msg("Ingesting Intelligence Feeds...")
	typeMap := make(map[string][]string)
	feedidMap := make(map[string]int)
	db, err := OpenDBConnection(logger)
	if err != nil {
		return err
	}
	for i := 0; i < len(feeds.Feeds); i++ {
		for _, j := range feeds.Feeds[i].Type {
			cat_err := InsertCategory(j, db)
			if cat_err != nil {
				logger.Error().Msg(cat_err.Error())
			}
		}
		feed_insert_err, feed_id := InsertFeed(feeds.Feeds[i].Name, feeds.Feeds[i].URL, db)
		if feed_insert_err != nil {
			logger.Error().Msg(feed_insert_err.Error())
		}

		feedidMap[feeds.Feeds[i].Name] = feed_id
		typeMap[feeds.Feeds[i].Name] = feeds.Feeds[i].Type
	}

	intelFiles, err := os.ReadDir(intelDir)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	for _, e := range intelFiles {
		baseNameWithoutExtension := strings.TrimSuffix(filepath.Base(e.Name()), filepath.Ext(e.Name()))
		_, exist := typeMap[baseNameWithoutExtension]
		if !exist {
			// Indicates the file is not one we downloaded in this process - some external intel or something else.
			continue
		}
		//err = IngestFile(fmt.Sprintf("%v\\%v", intelDir, e.Name()), typeMap[baseNameWithoutExtension], urlMap[baseNameWithoutExtension], db, logger)
		err = IngestFile(fmt.Sprintf("%v\\%v", intelDir, e.Name()), strings.Join(typeMap[baseNameWithoutExtension], ","), feedidMap[baseNameWithoutExtension], db, logger)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
	}
	return nil
}

func IngestFile(inputFile string, categories string, feedid int, db *sql.DB, logger zerolog.Logger) error {
	logger.Info().Msgf("Ingesting %v", inputFile)
	fileLines := FileToSlice(inputFile, logger)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("insert or ignore into ips(ip, feed, category) values(?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, line := range fileLines {
		lineTrimmed := strings.TrimSpace(line)
		if strings.HasPrefix(lineTrimmed, "#") {
			continue
		}
		v, e := RegexFirstPublicIPFromString(lineTrimmed)
		if e {
			ipParse := net.ParseIP(v)
			if ipParse == nil {
				continue
			}
			if IsPrivateIP(ipParse, v) {
				continue
			}
			if strings.Contains(categories, ",") {
				cats := strings.Split(categories, ",")
				for _, cat := range cats {
					ingestRecord(v, CategoryMap[cat], feedid, stmt, logger)
				}
			} else {
				ingestRecord(v, CategoryMap[categories], feedid, stmt, logger)
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func ingestRecord(ip string, category int, feed int, stmt *sql.Stmt, logger zerolog.Logger) {
	if ip != "" && category != 0 && feed != 0 {
		_, err := stmt.Exec(ip, feed, category)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
	}
}

func GetFeedIDIfExist(feed_name string, db *sql.DB) int {
	query := fmt.Sprintf("select feed_id from feeds where feed_name = \"%v\"", feed_name)
	rows, err := db.Query(query)
	defer rows.Close()
	if err != nil {
		return 0
	}
	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		return id
	}
	return 0
}

func InsertFeed(feed_name string, feed_url string, db *sql.DB) (error, int) {

	feed_id := GetFeedIDIfExist(feed_name, db)
	if feed_id != 0 {
		return nil, feed_id
	}
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("insert or ignore into feeds(feed_url, feed_name) values(?, ?)")
	_, cerr := stmt.Exec(feed_url, feed_name)
	if cerr != nil {
		return cerr, 0
	}
	tx.Commit()
	feed_id = GetFeedIDIfExist(feed_name, db)
	if feed_id != 0 {
		return nil, feed_id
	}
	return nil, 0
}

func InsertCategory(category string, db *sql.DB) error {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("insert or ignore into categories(category_value) values(?)")
	_, cerr := stmt.Exec(category)
	if cerr != nil {
		return cerr
	}
	tx.Commit()
	query := fmt.Sprintf("select category_id from categories where category_value = \"%v\"", category)
	rows, err := db.Query(query)
	defer rows.Close()
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		CategoryMap[category] = id
	}
	return nil
}

func CheckIPinTI(ip string, db *sql.DB) (string, string, string, bool, error) {
	query := fmt.Sprintf("select feeds.feed_name,categories.category_value from ips INNER JOIN categories ON ips.category = categories.category_id INNER JOIN feeds ON ips.feed = feeds.feed_id where ip=\"%v\"", ip)
	rows, err := db.Query(query)
	if err != nil {
		return "", "", "", false, err
	}
	defer rows.Close()
	categories := make([]string, 0)
	feed_names := make([]string, 0)
	for rows.Next() {
		results := iPCheckResults{
			feed_name: "",
			category:  "",
		}
		err = rows.Scan(&results.feed_name, &results.category)
		if err != nil {
			return "", "", "", false, err
		}
		categories = append(categories, results.category)
		feed_names = append(feed_names, results.feed_name)
		//return iptype, true, nil
	}
	if isDataCenter {
		categories = append(categories, "dc")
		feed_names = append(feed_names, "internal datacenter list")
	}
	categories = deduplicateStringSlice(categories)
	feed_names = deduplicateStringSlice(feed_names)
	if len(feed_names) == 0 {
		return "", "", "", false, err
	}
	feed_count := len(feed_names)
	feeds := strings.Join(feed_names, "|")
	cats := strings.Join(categories, "|")
	//fmt.Println(feed_count, feeds, cats)

	err = rows.Err()
	if err != nil {
		return "", "", "", false, err
	}

	return cats, feeds, strconv.Itoa(feed_count), true, nil
}

func IngestIPNetLists(url string, name string, file string, listtype string, category string, logger zerolog.Logger) {

	dest := fmt.Sprintf("%v\\%v", intelDir, file)
	dlerr := DownloadFile(logger, url, dest, "")
	if dlerr != nil {
		logger.Error().Msgf("Error Updating %v List: %v", listtype, dlerr.Error())
		return
	}
	ipList := FileToSlice(dest, logger)
	db, dberr := OpenDBConnection(logger)
	if dberr != nil {
		logger.Error().Msg(dberr.Error())
		return
	}
	err := InsertCategory(category, db)
	err, feed_id := InsertFeed(name, url, db)

	tx, err := db.Begin()
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	stmt, err := tx.Prepare("insert or ignore into ips(ip, feed, category) values(?, ?, ?)")
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer stmt.Close()
	logger.Info().Msgf("Ingesting %v", dest)
	for _, v := range ipList {
		gen, err := NewIPNetGenerator(v)
		if err != nil {
			continue
		}
		for ip := gen.Next(); ip != nil; ip = gen.Next() {
			ingestRecord(ip.String(), CategoryMap[category], feed_id, stmt, logger)
		}
	}
	err = tx.Commit()
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
}

func UpdateDCList(logger zerolog.Logger) {
	url := "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
	name := "dc_full_feed_X4BNet"
	file := "dc_full_feed_X4BNet.txt"
	IngestIPNetLists(url, name, file, "Datacenter", "dc", logger)
}

func UpdateVPNList(logger zerolog.Logger) {
	url := "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
	name := "vpn_full_feed_X4BNet"

	file := "vpn_full_feed_X4BNet.txt"
	IngestIPNetLists(url, name, file, "VPN", "vpn", logger)

}

// TODO - Consider crawling github repos in another config set
// https://github.com/volexity/threat-intel/tree/main
// https://github.com/vuldb/cyber_threat_intelligence
// https://github.com/Cisco-Talos/IOCs
// https://github.com/avast/ioc
