package shield_policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	consul "github.com/hashicorp/consul/api"
	ConsulWatcher "github.com/pteich/consul-kv-watcher"
)

type ServiceConfig struct {
	debugLevel     string
	tenantSettings map[string]TenantSettings
	tenantHashes   map[string]int
	sync.RWMutex
}

type RateLimitSettings struct {
	requestsPerInterval int
	intervalSeconds     int
	enabled             bool
}

type TenantSettings struct {
	mode        string
	serviceKeys []TenantAdministratorsJSON
	rateLimit   RateLimitSettings
	blockIP     string
}

type TenantInfoJSON struct {
	DoH                        string
	DoHRequestsPerInterval     int
	DoHRequestsIntervalSeconds int
}

type TenantAdministratorsJSON struct {
	username      string
	passwordHash  string
	Type          string `json:"type"`
	role          string
	email         string
	notifications bool
}

type TenantSettingsJSON struct {
	doh_blockIP string
}

const TENANT_HASHES_CHECK_INTERVAL = 5 * time.Minute

var KEYS_STEP = getEnvInt("KEYS_STEP", 1000)
var KEYS_SLEEP_SEC = getEnvInt("KEYS_SLEEP_SEC", 1)

var consulClient *consul.Client
var config *ServiceConfig
var timestampLastKVChangeProcessing = time.Now().Unix()

func init() {

	var err error
	config = &ServiceConfig{
		debugLevel:     "info",
		tenantSettings: map[string]TenantSettings{},
		tenantHashes:   map[string]int{},
	}

	consulClient, err = consul.NewClient(&consul.Config{
		Address: "localhost:8500",
	})
	if err != nil {
		panic(err) // TODO no panic?
	}

	go consulWatchJSON("settings/es-doh", func(data map[string]string) {
		config.Lock()
		config.debugLevel = data["debugLevel"]
		config.Unlock()
		// TODO apply log level to logger
	})

	go watchTenantSettings()

}

func watchTenantSettings() {
	var tenantIDs []string
	if err := consulGetJSON("tenantView/IDs", &tenantIDs); err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Printf("tenantView/IDs: %v\n", tenantIDs)

	var tenantsHashes map[string]int
	if err := consulGetJSON("tenantsHashes", &tenantsHashes); err != nil {
		fmt.Println(err)
	}

	fmt.Printf("tenantsHashes: %v\n", &tenantsHashes)

	for idx, tenantId := range tenantIDs {
		gotSettings := updateTenantSettings(tenantId)
		hash, hasHash := tenantsHashes[tenantId]

		if gotSettings && hasHash {
			setTenantHash(tenantId, hash)
		}

		if idx%KEYS_STEP == 0 {
			time.Sleep(time.Second * time.Duration(KEYS_SLEEP_SEC))
		}
	}

	fmt.Printf("settings: %+v\n", config)

	runIntervalBetween(checkHashesInterval, TENANT_HASHES_CHECK_INTERVAL)

	consulWatchJSON("tenantSettingsKVChanges", func(data []TenantSettingsKVChangeJSON) {
		fmt.Printf("tenantSettingsKVChanges %+v\n", data)
		for _, change := range data {
			if change.Timestamp < timestampLastKVChangeProcessing {
				continue
			}
			tenantID := change.TenantID

			if change.Hash == getTenantHash(tenantID) {
				continue
			}

			fmt.Printf("Reloading tenant ID %s from consul\n", tenantID)

			if updateTenantSettings(tenantID) {
				setTenantHash(tenantID, change.Hash)
			}

		}

		timestampLastKVChangeProcessing = time.Now().Unix()

	})
}

type TenantSettingsKVChangeJSON struct {
	TenantID  string `json:"tenantID"`
	Hash      int    `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

func checkHashesInterval() {
	fmt.Printf("Checking hashes...\n")

	var tenantsHashes map[string]int
	if err := consulGetJSON("tenantsHashes", &tenantsHashes); err != nil {
		fmt.Println(err)
	}

	for tenantId, hash := range tenantsHashes {
		currentHash := getTenantHash(tenantId)

		if currentHash == hash {
			continue
		}

		fmt.Printf("Tenant ID %s in-memory hash %d does not mach farm-sync hash %d\n", tenantId, currentHash, hash)

		if updateTenantSettings(tenantId) {
			setTenantHash(tenantId, hash)
		}
	}
}

func updateTenantSettings(tenantId string) bool {
	settings := &TenantSettings{
		mode: "None",
		rateLimit: RateLimitSettings{
			requestsPerInterval: 100,
			intervalSeconds:     60,
			enabled:             false,
		},
	}

	var tenantInfo TenantInfoJSON
	if err := consulGetJSON(fmt.Sprintf("tenantSettings/%s/tenantInfo", tenantId), &tenantInfo); err != nil {
		fmt.Println(err)
		return false
	}

	fmt.Printf("tenantInfo %s %v\n", tenantId, tenantInfo)

	settings.mode = tenantInfo.DoH
	if tenantInfo.DoHRequestsPerInterval != 0 {
		settings.rateLimit.requestsPerInterval = tenantInfo.DoHRequestsPerInterval
	}
	if tenantInfo.DoHRequestsIntervalSeconds != 0 {
		settings.rateLimit.intervalSeconds = tenantInfo.DoHRequestsIntervalSeconds
	}
	if tenantInfo.DoHRequestsPerInterval != 0 && tenantInfo.DoHRequestsIntervalSeconds != 0 {
		settings.rateLimit.enabled = true
	}

	var tenantAdmins []TenantAdministratorsJSON
	if err := consulGetJSON(fmt.Sprintf("tenantSettings/%s/administrators", tenantId), &tenantAdmins); err != nil {
		fmt.Println(err)
		return false
	}

	for _, value := range tenantAdmins {
		if value.Type == "Service key" {
			settings.serviceKeys = append(settings.serviceKeys, value)
		}
	}

	var tenantSettings TenantSettingsJSON
	if err := consulGetJSON(fmt.Sprintf("tenantSettings/%s/settings", tenantId), &tenantSettings); err != nil {
		fmt.Println(err)
		return false
	}

	settings.blockIP = tenantSettings.doh_blockIP

	config.RWMutex.Lock()
	config.tenantSettings[tenantId] = *settings
	config.RWMutex.Unlock()

	return true
}

func consulGetJSON(key string, data any) error {
	kv := consulClient.KV()

	pair, _, err := kv.Get(key, nil)
	if err != nil || pair == nil {
		return fmt.Errorf("failed to get Consul KV %s %w", key, err)
	}
	if err := json.Unmarshal(pair.Value, data); err != nil {
		return fmt.Errorf("failed to Parse Consul KV %s %v", key, err)
	}
	return nil
}

func consulWatchJSON[T any](key string, callback func(data T)) {
	watcher := ConsulWatcher.New(consulClient, 5*time.Second, 5*time.Second)
	kvPairs, err := watcher.WatchKey(context.Background(), key)

	if err != nil {
		panic(err) // TODO no panic
	}
	for {
		pair := <-kvPairs
		if pair == nil { // TODO key does not exist case?
			continue
		}

		var data T

		if err := json.Unmarshal(pair.Value, &data); err != nil {
			fmt.Println("Error parsing JSON response", err)
			return // TODO maybe continue?
		}
		callback(data)
	}
}

func getTenantHash(tenantId string) int {
	config.RLock()
	defer config.RUnlock()
	return config.tenantHashes[tenantId]
}

func setTenantHash(tenantId string, hash int) {
	config.Lock()
	defer config.Unlock()
	config.tenantHashes[tenantId] = hash
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		i, err := strconv.Atoi(value)
		if err != nil {
			return fallback
		}
		return i
	}
	return fallback
}

// this will wait a fixed delay amount between one task finishing and the next starting
func runIntervalBetween(fn func(), delay time.Duration) chan bool {
	stop := make(chan bool)

	go func() {
		for {
			fn()
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}
	}()

	return stop
}
