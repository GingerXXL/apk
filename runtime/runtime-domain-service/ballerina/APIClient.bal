//
// Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

import ballerina/http;
import ballerina/log;
import ballerina/uuid;
import runtime_domain_service.model;
import runtime_domain_service.org.wso2.apk.runtime.model as runtimeModels;
import runtime_domain_service.org.wso2.apk.apimgt.api.model as apkAPis;
import runtime_domain_service.java.util as utilapis;
import runtime_domain_service.org.wso2.apk.apimgt.api;
import ballerina/jwt;
import runtime_domain_service.org.wso2.apk.runtime as runtimeUtil;

public class APIClient {

    public function getAPIDefinitionByID(string id) returns string|NotFoundError|NotAcceptableError {
        model:K8sAPI|error api = getAPI(id);
        if api is model:K8sAPI {
            if api.definitionFileRef.length() > 0 {
                string|error definition = self.getDefinition(api);
                if definition is string {
                    return definition;
                } else {
                    log:printError("Error while reading definition:", definition);
                }
            }
        }
        NotFoundError notfound = {body: {code: 909100, message: id + "not found."}};
        return notfound;
    }

    private function getDefinition(model:K8sAPI api) returns string|error {
        json|error configMapValue = getConfigMapValueFromNameAndNamespace(api.definitionFileRef, api.namespace);
        if configMapValue is json {
            json|error data = configMapValue.data;
            json|error binaryData = configMapValue.binaryData;
            if data is json {
                map<json> dataMap = <map<json>>data;
                string[] keys = dataMap.keys();
                if keys.length() == 1 {
                    return dataMap.get(keys[0]).toJsonString();
                }
            } else if binaryData is json {
                map<json> dataMap = <map<json>>binaryData;
                string[] keys = dataMap.keys();
                if keys.length() == 1 {
                    return dataMap.get(keys[0]).toJsonString();
                }
            }
            return "";
        } else {
            return configMapValue;
        }
    }

    //Get APIs deployed in default namespace by APIId.
    public function getAPIById(string id) returns API|NotFoundError|BadRequestError {
        boolean APIIDAvailable = id.length() > 0 ? true : false;
        if (APIIDAvailable && string:length(id.toString()) > 0)
        {
            model:K8sAPI? api = apilist[id];
            if api != null {
                API detailedAPI = convertK8sAPItoAPI(api);
                return detailedAPI;
            } else {
                NotFoundError notfound = {body: {code: 909100, message: id + "not found."}};
                return notfound;
            }
        }
        BadRequestError badRequestError = {body: {code: 900910, message: "missing required attributes"}};
        return badRequestError;
    }

    //Delete APIs deployed in a namespace by APIId.
    public function deleteAPIById(string id) returns http:Ok|ForbiddenError|NotFoundError|ConflictError|PreconditionFailedError {
        boolean APIIDAvailable = id.length() > 0 ? true : false;
        if (APIIDAvailable && string:length(id.toString()) > 0)
        {
            model:K8sAPI|error api = getAPI(id);
            if api is model:K8sAPI {
                json|http:ClientError apiCRDeletionResponse = deleteAPICR(api.k8sName, api.namespace);
                if apiCRDeletionResponse is http:ClientError {
                    log:printError("Error while undeploying API CR ", apiCRDeletionResponse);
                }
                json|http:ClientError apiDefinitionDeletionResponse = deleteConfigMap(api.definitionFileRef, api.namespace);
                if apiDefinitionDeletionResponse is http:ClientError {
                    log:printError("Error while undeploying API definition ", apiDefinitionDeletionResponse);
                }
                string? prodHTTPRouteRef = api.prodHTTPRouteRef;
                if prodHTTPRouteRef is string && prodHTTPRouteRef.toString().length() > 0 {
                    json|http:ClientError prodHttpRouteDeletionResponse = deleteHttpRoute(prodHTTPRouteRef, api.namespace);
                    if prodHttpRouteDeletionResponse is http:ClientError {
                        log:printError("Error while undeploying prod http route ", prodHttpRouteDeletionResponse);
                    }
                }
                string? sandBoxHttpRouteRef = api.sandHTTPRouteRef;
                if sandBoxHttpRouteRef is string && sandBoxHttpRouteRef.toString().length() > 0 {
                    json|http:ClientError sandHttpRouteDeletionResponse = deleteHttpRoute(sandBoxHttpRouteRef, api.namespace);
                    if sandHttpRouteDeletionResponse is http:ClientError {
                        log:printError("Error while undeploying prod http route ", sandHttpRouteDeletionResponse);
                    }
                }
            } else {
                NotFoundError apiNotfound = {body: {code: 900910, description: "API with " + id + " not found", message: "API not found"}};
                return apiNotfound;
            }
        }
        PreconditionFailedError badRequestError = {body: {code: 900910, message: "missing required attributes"}};
        return badRequestError;
    }

    //Get all deployed APIs in namespace with specific search query
    public function getAPIListInNamespaceWithQuery(string? query, int 'limit = 25, int offset = 0, string sortBy = "createdTime", string sortOrder = "desc") returns APIList|InternalServerErrorError|BadRequestError|error {
        APIInfo[] apiNames = map:toArray(apilist);
        return {list: apiNames, count: apiNames.length(), pagination: {total: apilist.length()}};
    }

    # This returns list of APIS.
    #
    # + return - Return list of APIS in namsepace.
    public function getAPIList() returns APIList|error {
        API[] apilist = [];
        foreach model:K8sAPI api in getAPIs() {
            API convertedModel = convertK8sAPItoAPI(api);
            apilist.push(convertedModel);
        }
        APIList APIList = {
            list: apilist
        };
        return APIList;
    }

    public function createAPI(API api) returns string|Error {
        if (self.validateName(api.name)) {
            return {code: 90911, message: "API Name `${api.name}` already exist.", description: "API Name `${api.name}` already exist."};
        }
        if self.validateContextAndVersion(api.context, api.'version) {
            return {code: 90912, message: "API Context `${api.context}` already exist.", description: "API Context `${api.context}` already exist."};
        }
        return "created";
    }

    private function validateContextAndVersion(string context, string 'version) returns boolean {

        foreach model:K8sAPI k8sAPI in getAPIs() {
            if k8sAPI.context == self.returnFullContext(context, 'version) {
                return true;
            }
        }
        return false;
    }

    private function returnFullContext(string context, string 'version) returns string {
        string fullContext = context;
        if (!string:endsWith(context, 'version)) {
            fullContext = string:'join("/", context, 'version);
        }
        return fullContext;
    }

    function validateName(string name) returns boolean {
        foreach model:K8sAPI k8sAPI in getAPIs() {
            if k8sAPI.apiDisplayName == name {
                return true;
            }
        }
        return false;
    }

    function createAndDeployAPI(API api) {
        model:API k8sAPI = self.convertK8sCrAPI(api);
        log:printInfo(<string>k8sAPI.toJson());
    }

    function convertK8sCrAPI(API api) returns model:API {
        model:API apispec = {
            metadata: {name: api.name.concat(api.'version), namespace: getNameSpace(runtimeConfiguration.apiCreationNamespace)},
            spec: {
                apiDisplayName: api.name,
                apiType: api.'type,
                apiVersion: api.'version,
                context: self.returnFullContext(api.context, api.'version),
                definitionFileRef: "",
                prodHTTPRouteRef: "",
                sandHTTPRouteRef: ""
            }
        };
        return apispec;
    }

    function createAPIFromService(string serviceKey, API api) returns CreatedAPI|NotFoundError|InternalServerErrorError|ConflictError {
        if (self.validateName(api.name)) {
            ConflictError conflictError = {body: {code: 90911, message: "API Name `${api.name}` already exist.", description: "API Name `${api.name}` already exist."}};
            return conflictError;
        }
        if self.validateContextAndVersion(api.context, api.'version) {
            ConflictError conflictError = {body: {code: 90911, message: "API Name `${api.context}` already exist.", description: "API Name `${api.name}` already exist."}};
            return conflictError;
        }
        self.setDefaultOperationsIfNotExist(api);
        Service|error serviceRetrieved = grtServiceById(serviceKey);
        string uniqueId = uuid:createType1AsString();
        if serviceRetrieved is Service {
            model:Httproute prodHttpRoute = self.retrieveHttpRoute(api, serviceRetrieved, uniqueId, "production");
            model:API k8sAPI = self.generateAPICRArtifact(api, (), prodHttpRoute, uniqueId);
            model:K8sServiceMapping k8sServiceMapping = self.generateK8sServiceMapping(k8sAPI, serviceRetrieved, getNameSpace(runtimeConfiguration.apiCreationNamespace), uniqueId);
            string|error generatedSwaggerDefinition = self.retrieveGeneratedSwaggerDefinition(api);
            model:ConfigMap definitionConnfigMap;
            if generatedSwaggerDefinition is string {
                definitionConnfigMap = self.retrieveGeneratedConfigmapForDefinition(api, generatedSwaggerDefinition, uniqueId);
            } else {
                InternalServerErrorError internalEror = {body: {code: 90900, message: "Internal Error while generating definition"}};
                return internalEror;
            }
            json|http:ClientError deployConfigMapResult = deployConfigMap(definitionConnfigMap, getNameSpace(runtimeConfiguration.apiCreationNamespace));
            if deployConfigMapResult is json {
                log:printDebug("Deployed Configmap Successfully" + deployConfigMapResult.toJsonString());
            } else {
                log:printError("Error while deploying Configmap", deployConfigMapResult);

                InternalServerErrorError internalEror = {body: {code: 90900, message: "Internal Error while generating definition"}};
                return internalEror;
            }
            json|http:ClientError deployHttpRouteResult = deployHttpRoute(prodHttpRoute, getNameSpace(runtimeConfiguration.apiCreationNamespace));
            if deployHttpRouteResult is json {
                log:printDebug("Deployed HttpRoute Successfully" + deployHttpRouteResult.toJsonString());
            } else {
                log:printError("Error while deploying Httproute", deployHttpRouteResult);
                InternalServerErrorError internalEror = {body: {code: 90900, message: "Internal Error while Deploying Httproute"}};
                return internalEror;
            }

            json|http:ClientError deployAPICRResult = deployAPICR(k8sAPI, getNameSpace(runtimeConfiguration.apiCreationNamespace));
            if deployAPICRResult is json {
                log:printDebug("Deployed K8sAPI Successfully" + deployAPICRResult.toJsonString());
            } else {
                log:printError("Error while deploying API", deployAPICRResult);
                InternalServerErrorError internalEror = {body: {code: 90900, message: "Internal Error while Deploying K8sAPI"}};
                return internalEror;
            }

            json|http:ClientError deployServiceMappingCRResult = deployServiceMappingCR(k8sServiceMapping, getNameSpace(runtimeConfiguration.apiCreationNamespace));
            if deployServiceMappingCRResult is json {
                log:printDebug("Deployed K8sAPI Successfully" + deployServiceMappingCRResult.toJsonString());
            } else {
                log:printError("Error while deploying API", deployServiceMappingCRResult);
                InternalServerErrorError internalEror = {body: {code: 90900, message: "Internal Error while Deploying K8sAPI"}};
                return internalEror;
            }

        } else {
            NotFoundError notfound = {body: {code: 90913, message: "Service from " + serviceKey + " not found."}};
            return notfound;
        }
        CreatedAPI createdAPI = {body: {name: api.name, context: self.returnFullContext(api.context, api.'version), 'version: api.'version}};
        return createdAPI;

    }

    private function retrieveGeneratedConfigmapForDefinition(API api, string generatedSwaggerDefinition, string uniqueId) returns model:ConfigMap {
        map<string> configMapData = {};
        if api.'type == API_TYPE_HTTP {
            configMapData["openapi.json"] = generatedSwaggerDefinition;
        }
        model:ConfigMap configMap = {
            metadata: {
                name: self.retrieveDefinitionName(api, uniqueId),
                namespace: getNameSpace(runtimeConfiguration.apiCreationNamespace)
            },
            data: configMapData
        };
        return configMap;
    }

    private function setDefaultOperationsIfNotExist(API api) {
        APIOperations[]? operations = api.operations;
        boolean operationsAvailable;
        if operations is APIOperations[] && operations.length() == 0 {
            operationsAvailable = false;
        } else {
            operationsAvailable = false;
        }
        if operationsAvailable == false {
            APIOperations[] apiOperations = [];
            if api.'type == API_TYPE_HTTP {
                foreach string httpverb in HTTP_DEFAULT_METHODS {
                    APIOperations apiOperation = {target: "/*", verb: httpverb.toUpperAscii()};
                    apiOperations.push(apiOperation);
                }
                api.operations = apiOperations;
            }
        }
    }

    private function generateAPICRArtifact(API api, model:Httproute? sandboxHttp, model:Httproute? prodHttp, string uniqueId) returns model:API {
        model:API k8sAPI = {
            metadata: {
                name: uniqueId,
                namespace: getNameSpace(runtimeConfiguration.apiCreationNamespace)
            },
            spec: {
                apiDisplayName: api.name,
                apiType: api.'type,
                apiVersion: api.'version,
                context: self.returnFullContext(api.context, api.'version),
                definitionFileRef: self.retrieveDefinitionName(api, uniqueId)
            }
        };
        if (prodHttp is model:Httproute) {
            k8sAPI.spec.prodHTTPRouteRef = self.retrieveHttpRouteRefName(api, uniqueId, "production");
        }
        if (sandboxHttp is model:Httproute) {
            k8sAPI.spec.sandHTTPRouteRef = self.retrieveHttpRouteRefName(api, uniqueId, "sandbox");
        }
        return k8sAPI;
    }

    private function retrieveDefinitionName(API api, string uniqueId) returns string {
        return uniqueId + "-definition";
    }

    private function retrieveHttpRouteRefName(API api, string uniqueId, string 'type) returns string {
        return uniqueId + "-" + 'type;
    }

    private function retrieveHttpRoute(API api, Service? serviceEntry, string uniqueId, string 'type) returns model:Httproute {
        model:Httproute httpRoute = {
            metadata:
                {
                name: self.retrieveHttpRouteRefName(api, uniqueId, 'type),
                namespace: getNameSpace(runtimeConfiguration.apiCreationNamespace)
            },
            spec: {
                parentRefs: self.generateAndRetrieveParentRefs(api, serviceEntry, uniqueId),
                rules: self.generateHttpRouteRules(api, serviceEntry),
                hostnames: self.getHostNames(api, uniqueId, 'type)
            }
        };
        return httpRoute;
    }

    private function getHostNames(API api, string unoqueId, string 'type) returns string[] {
        return ["gw.wso2.com"];
    }

    private function generateAndRetrieveParentRefs(API api, Service? serviceEntry, string uniqueId) returns model:ParentReference[] {
        model:ParentReference[] parentRefs = [];
        model:ParentReference parentRef = {group: "gateway.networking.k8s.io", kind: "Gateway", name: "Default"};
        parentRefs.push(parentRef);
        return parentRefs;
    }

    private function generateHttpRouteRules(API api, Service? serviceEntry) returns model:HTTPRouteRule[] {
        model:HTTPRouteRule[] httpRouteRules = [];
        model:HTTPRouteRule httpRouteRule = {matches: self.retrieveMatches(api), backendRefs: self.retrieveGeneratedBackend(api, serviceEntry)};
        httpRouteRules.push(httpRouteRule);
        return httpRouteRules;
    }

    private function retrieveGeneratedBackend(API api, Service? serviceEntry) returns model:HTTPBackendRef[] {
        if serviceEntry is Service {
            model:HTTPBackendRef httpBackend = {
                namespace:
            serviceEntry.namespace,
                kind: "Service",
                weight: 1,
                port: self.retrievePort(serviceEntry),
                name: serviceEntry.name,
                group: ""
            };
            return [httpBackend];

        } else {
            //TODO tharindua@wso2.com need to write once resource level endpoint came.
            return [{port: 0, kind: "", name: "", namespace: "", weight: 0, group: ""}];
        }
    }

    private function retrievePort(Service serviceEntry) returns int {
        PortMapping[]? portmappings = serviceEntry.portmapping;
        if portmappings is PortMapping[] {
            if portmappings.length() > 0 {
                return portmappings[0].targetport;
            }
        }

        return 80;
    }

    private function retrieveMatches(API api) returns model:HTTPRouteMatch[] {
        model:HTTPRouteMatch[] httpRouteMatch = [];
        APIOperations[]? operations = api.operations;
        if operations is APIOperations[] {
            foreach APIOperations operation in operations {
                model:HTTPRouteMatch httpRoute = {method: <string>operation.verb, path: {'type: "PathPrefix", value: self.returnFullContext(api.context, api.'version) + <string>operation.target}};
                httpRouteMatch.push(httpRoute);
            }
        }
        return httpRouteMatch;
    }

    private function retrieveGeneratedSwaggerDefinition(API api) returns string|error {
        runtimeModels:API api1 = runtimeModels:newAPI1();
        api1.setName(api.name);
        api1.setType(api.'type);
        api1.setVersion(api.'version);
        utilapis:Set uritemplatesSet = utilapis:newHashSet1();
        if api.operations is APIOperations[] {
            foreach APIOperations apiOperation in <APIOperations[]>api.operations {
                apkAPis:URITemplate uriTemplate = apkAPis:newURITemplate1();
                uriTemplate.setUriTemplate(<string>apiOperation.target);
                string? verb = apiOperation.verb;
                if verb is string {
                    uriTemplate.setHTTPVerb(verb.toUpperAscii());
                }
                _ = uritemplatesSet.add(uriTemplate);
            }
        }
        api1.setUriTemplates(uritemplatesSet);
        string?|api:APIManagementException retrievedDefinition = runtimeUtil:RuntimeAPICommonUtil_generateDefinition(api1);
        if retrievedDefinition is string {
            return retrievedDefinition;
        } else if retrievedDefinition is () {
            return "";
        } else {
            return error(retrievedDefinition.message());
        }
    }

    public function generateAPIKey(string apiId) returns APIKey|BadRequestError|NotFoundError|InternalServerErrorError {
        model:K8sAPI|error api = getAPI(apiId);
        if api is model:K8sAPI {
            InternalTokenGenerator tokenGenerator = new ();
            string|jwt:Error generatedToken = tokenGenerator.generateToken(api, APK_USER);
            if generatedToken is string {
                APIKey apiKey = {apikey: generatedToken, validityTime: <int>runtimeConfiguration.tokenIssuerConfiguration.expTime};
                return apiKey;
            } else {
                log:printError("Error while Genereting token for API : " + apiId, generatedToken);
                InternalServerErrorError internalError = {body: {code: 90911, message: "Error while Generating Token"}};
                return internalError;
            }
        } else {
            NotFoundError notfound = {body: {code: 909100, message: apiId + "not found."}};
            return notfound;
        }
    }

    public function retrieveAllApisAtStartup(string? continueValue) returns error? {
        string? resultValue = continueValue;
        json|http:ClientError retrieveAllAPISResult;
        if resultValue is string {
            retrieveAllAPISResult = retrieveAllAPIS(resultValue);
        } else {
            retrieveAllAPISResult = retrieveAllAPIS(());
        }

        if retrieveAllAPISResult is json {
            json metadata = check retrieveAllAPISResult.metadata;
            json[] items = <json[]>check retrieveAllAPISResult.items;
            putallAPIS(items);

            json|error continueElement = metadata.'continue;
            if continueElement is json {
                if (<string>continueElement).length() > 0 {
                    _ = check self.retrieveAllApisAtStartup(<string?>continueElement);
                }
            }
            string resourceVersion = <string>check metadata.'resourceVersion;
            setResourceVersion(resourceVersion);
        }
    }
    function generateK8sServiceMapping(model:API api, Service serviceEntry, string namespace, string uniqueId) returns model:K8sServiceMapping {
        model:K8sServiceMapping k8sServiceMapping = {
            metadata: {
                name: self.getServiceMappingEntryName(uniqueId),
                namespace: namespace
            },
            spec: {
                serviceRef: {
                    namespace: serviceEntry.namespace,
                    name: serviceEntry.name
                },
                apiRef: {
                    namespace: api.metadata.namespace,
                    name: api.metadata.name
                }
            }
        };
        return k8sServiceMapping;

    }
    function getServiceMappingEntryName(string uniqueId) returns string {
        return uniqueId + "-servicemapping";
    }
}

