package shield_policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coredns/coredns/plugin/shield_policy/logs"
	pb "github.com/coredns/coredns/plugin/shield_policy/proto"
	"github.com/dgraph-io/ristretto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

// TODO use struct with json fields defined
// TODO should be a separate library
// TODO return error, don't return 0 on error?

var client = &http.Client{
	Timeout: time.Second * 10,
	// use http2:
	// Transport: &http2.Transport{
	// 	// So http2.Transport doesn't complain the URL scheme isn't 'https'
	// 	AllowHTTP: true,
	// 	// Pretend we are dialing a TLS endpoint. (Note, we ignore the passed tls.Config)
	// 	DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	// 		var d net.Dialer
	// 		return d.DialContext(ctx, network, addr)
	// 	},
	// },
}

var grpcPolicyClient pb.PolicyManagerClient
var cache *ristretto.Cache

func init() {
	// TODO put GRPC behind flag
	// gRPC init
	policyManagerHostname := "127.0.0.1"
	grpcPort := "3002"
	if inDocker {
		policyManagerHostname = "es-policy-manager.farm-services.svc.cluster.local"
	}

	serverAddr := policyManagerHostname + ":" + grpcPort

	var opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(serverAddr, opts...)

	if err != nil {
		log.Errorf("Fail to dial GRPC %v\n", err)
		// return 0
	}
	// defer conn.Close()

	grpcPolicyClient = pb.NewPolicyManagerClient(conn)

	// cache init
	cache, err = ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 29, // maximum cost of cache 512MB.
		BufferItems: 64,      // number of keys per Get buffer.
		Metrics:     true,
	})

	if err != nil {
		panic(err)
	}

}

// TODO refactor to use context, refactor into a class
func queryPolicy(logger *logs.CustomLogger, domain string, tenantID string) (*pb.PolicyResponse, error) {

	cacheKey := domain + tenantID
	value, hit := cache.Get(cacheKey)

	if hit {
		return value.(*pb.PolicyResponse), nil
	}

	policyManagerHostname := "127.0.0.1"
	port := "3001"

	if inDocker {
		policyManagerHostname = "es-policy-manager.farm-services.svc.cluster.local"
		port = "3000"
	}

	policyManagerURL := fmt.Sprintf("http://%s:%s/getpolicy", policyManagerHostname, port)

	// fmt.Printf("requesting policy manager: %v %v\n", domain, tenantID)
	requestBody, err := json.Marshal(map[string]any{
		"url":       domain,
		"user":      "-",
		"requestor": "es-doh",
		"tenantID":  tenantID,
	})
	// TODO re-format all errors
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", policyManagerURL, bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		logger.Error("error making HTTP request", zap.Error(err))
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed getting policy for domain '%s': %d %s\n", domain, resp.StatusCode, resp.Status)
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}

	data := &pb.PolicyResponse{}
	if protojson.Unmarshal(body, data); err != nil {
		fmt.Println("Error parsing JSON response", err)
		return nil, err
	}

	// var data map[string]any

	// if err := json.Unmarshal(body, &data); err != nil {
	// 	fmt.Println("Error parsing JSON response", err)
	// }

	// access := int(data["access"].(float64))

	// fmt.Printf("Access policy from policy-manager: %v", access)
	// fmt.Printf("Local Port: %s\n", body)

	// TODO take cache TTL from consul
	cache.SetWithTTL(cacheKey, data, 1, 600*time.Second)
	return data, nil
}

// this is probably incomplete, check above
func queryPolicyGRPC(domain string, tenantID string) int {
	req := &pb.PolicyRequest{
		Url:       domain,
		TenantID:  tenantID,
		Requestor: "es-doh",
		User:      "-",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := grpcPolicyClient.GetPolicy(ctx, req)

	if err != nil {
		log.Errorf("GRPC Fail to GetPolicy, %v", err)
		return 0
	}

	// log.Infof("grpc response: %v\n", res)

	return int(res.Access)

}

var inDocker = isDocker()

// TODO there was another way to check, check Nodejs is-docker package
func isDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	return false
}
