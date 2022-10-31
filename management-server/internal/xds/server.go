/*
 *  Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package xds

import (
	"APKManagementServer/internal/logger"
	"APKManagementServer/internal/xds/callbacks"
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	apkmgt_application "github.com/wso2/product-microgateway/adapter/pkg/discovery/api/wso2/discovery/apkmgt"
	apkmgt_service "github.com/wso2/product-microgateway/adapter/pkg/discovery/api/wso2/discovery/service/apkmgt"
	wso2_cache "github.com/wso2/product-microgateway/adapter/pkg/discovery/protocol/cache/v3"
	wso2_resource "github.com/wso2/product-microgateway/adapter/pkg/discovery/protocol/resource/v3"
	wso2_server "github.com/wso2/product-microgateway/adapter/pkg/discovery/protocol/server/v3"
	"google.golang.org/grpc"
)

var (
	apiCache wso2_cache.SnapshotCache
	// The labels with partition IDs are stored here. <LabelHirerarchy>-P:<partition_ID>
	// TODO: (VirajSalaka) change the implementation of the snapshot library to provide the same information.
	introducedLabels map[string]string
	apiCacheMutex    sync.Mutex
	Sent             bool = true
)

const (
	maxRandomInt             int    = 999999999
	typeURL                  string = "type.googleapis.com/wso2.discovery.ga.Api"
	grpcMaxConcurrentStreams        = 1000000
	port                            = 18000
)

// IDHash uses ID field as the node hash.
type IDHash struct{}

// ID uses the node ID field
func (IDHash) ID(node *corev3.Node) string {
	if node == nil {
		return "unknown"
	}
	return node.Id
}

var _ wso2_cache.NodeHash = IDHash{}

func init() {
	apiCache = wso2_cache.NewSnapshotCache(false, IDHash{}, nil)
	rand.Seed(time.Now().UnixNano())
	introducedLabels = make(map[string]string, 1)
}

//FeedData mock data
func FeedData() {
	logger.LoggerXdsServer.Debug("adding mock data")
	version := rand.Intn(maxRandomInt)
	applications := apkmgt_application.ApplicationDetails{
		Applications: []*apkmgt_application.Application{
			{
				Uuid: "apiUUID1",
				Name: "name1",
			},
		},
	}
	newSnapshot, _ := wso2_cache.NewSnapshot(fmt.Sprint(version), map[wso2_resource.Type][]types.Resource{
		wso2_resource.APKMgtApplicationType: {&applications},
	})
	apiCacheMutex.Lock()
	apiCache.SetSnapshot(context.Background(), "mine", newSnapshot)
	apiCacheMutex.Unlock()
}

func InitAPKMgtServer() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	apiCache := wso2_cache.NewSnapshotCache(false, IDHash{}, nil)
	apkMgtAPIDsSrv := wso2_server.NewServer(ctx, apiCache, &callbacks.Callbacks{})

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	grpcServer := grpc.NewServer(grpcOptions...)
	apkmgt_service.RegisterAPKMgtDiscoveryServiceServer(grpcServer, apkMgtAPIDsSrv)

	//todo (amaliMatharaarachchi) handle error gracefully
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.LoggerServer.Panicf("Error while listening on port: %v. Error: %v", port, err.Error())
	}

	logger.LoggerServer.Infof("APK Management server XDS is starting on port %v.", port)
	if err = grpcServer.Serve(listener); err != nil {
		logger.LoggerServer.Error("Error while starting APK Management server XDS.", err)
	}
}
