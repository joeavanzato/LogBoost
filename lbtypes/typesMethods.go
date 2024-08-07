package lbtypes

import (
	"github.com/oschwald/maxminddb-golang"
	"sync"
	"sync/atomic"
)

// https://github.com/oschwald/geoip2-golang/blob/main/reader.go
// TODO - Review potential MaxMind fields to determine usefulness of any others - really depends on the 'type' of DB we have access to
// Refactor to provide fields properly from IP/ASN
// lat/lon are kind of meh but I guess could be useful for some applications - but really it depends on accuracy radius which could maybe be useful here.
type City struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Traits struct {
		IsAnonymousProxy bool `maxminddb:"is_anonymous_proxy"`
	} `maxminddb:"traits"`
}

type ASN struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
}

type Domain struct {
	Domain string `maxminddb:"domain"`
}

type IPCache struct {
	ASNOrg    string
	Country   string
	City      string
	Domains   []string
	ThreatCat string
}

type DBRefs struct {
	Country *maxminddb.Reader
	City    *maxminddb.Reader
	Domain  *maxminddb.Reader
	ASN     *maxminddb.Reader
}

// IDB Data Struct
type ShodanIDBResponse struct {
	Cpes      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}
type ShodanIDBResponseFail struct {
	Detail string `json:"detail"`
}

// TODO - Put lock and map in single struct for organization - then refactor CheckIP and AddIP to just take the original cachemap struct
var IPCacheMap = make(map[string]IPCache)
var IPCacheMapLock = sync.RWMutex{}

// TODO - Measure performance and compare to using sync.Map instead
func CheckIP(ip string) (IPCache, bool) {
	IPCacheMapLock.RLock()
	defer IPCacheMapLock.RUnlock()
	v, e := IPCacheMap[ip]
	return v, e
}
func AddIP(ip string, ipcache IPCache) {
	IPCacheMapLock.Lock()
	defer IPCacheMapLock.Unlock()
	IPCacheMap[ip] = ipcache
}

type threadMap struct {
	data map[string]any
	lock sync.RWMutex
}

func (tm *threadMap) Set(key string, val any) {
	tm.lock.Lock()
	defer tm.lock.Unlock()
	tm.data[key] = val
}

func (tm *threadMap) Get(key string) (any, bool) {
	tm.lock.RLock()
	defer tm.lock.RUnlock()
	v, e := tm.data[key]
	return v, e
}

// Used to track overall data size processed by the script - accessed by multiple goroutines concurrently so we make it threadsafe
type SizeTracker struct {
	InputSizeMBytes      int
	OutputSizeMBytes     int
	Mw                   sync.RWMutex
	ActualFilesProcessed int
}

func (s *SizeTracker) AddBytes(in int, out int) {
	s.Mw.Lock()
	defer s.Mw.Unlock()
	s.InputSizeMBytes += in
	s.OutputSizeMBytes += out
	s.ActualFilesProcessed += 1
}

// Used to help keep track of jobs in a WaitGroup
type RunningJobs struct {
	JobCount int
	Mw       sync.RWMutex
}

func (job *RunningJobs) GetJobs() int {
	job.Mw.RLock()
	defer job.Mw.RUnlock()
	return job.JobCount
}
func (job *RunningJobs) AddJob() {
	job.Mw.Lock()
	defer job.Mw.Unlock()
	job.JobCount += 1
}
func (job *RunningJobs) SubJob() {
	job.Mw.Lock()
	defer job.Mw.Unlock()
	job.JobCount -= 1
}

// Should probably get rid of all of the below since it really isn't necessary now that we are using the jobs tracker instead of this to limit concurrency maxes
// ////
type WaitGroupCount struct {
	sync.WaitGroup
	count int64
}

func (wg *WaitGroupCount) Add(delta int) {
	atomic.AddInt64(&wg.count, int64(delta))
	wg.WaitGroup.Add(delta)
}

func (wg *WaitGroupCount) Done() {
	atomic.AddInt64(&wg.count, -1)
	wg.WaitGroup.Done()
}

func (wg *WaitGroupCount) GetCount() int {
	return int(atomic.LoadInt64(&wg.count))
}

// ////
