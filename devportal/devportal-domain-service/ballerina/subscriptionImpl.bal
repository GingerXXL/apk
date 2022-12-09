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

import ballerina/log;
import ballerina/uuid;
import ballerina/lang.value;

function addSubscription(Subscription payload, string org, string user) returns string?|Subscription|error {
    int apiId = 0;
    int appId = 0;
    int|error? subscriberId = getSubscriberIdDAO(user,org);
    if subscriberId !is int {
        string err = "Error while retrieving user by name " + user;
        log:printError(err);
        return error(err);
    } 
    string? apiUUID = payload.apiId;
    if apiUUID is string {
        string?|API|error api = getAPIByAPIId(apiUUID, org);
        if api !is API {
            string err = "Error while retrieving API by provided id" + apiUUID;
            log:printError(err);
            return error(err);
        }
        string apiInString = api.toJsonString();
        json j = check value:fromJsonString(apiInString);
        apiId = check j.api_id.ensureType();
    }
    string? appUUID = payload.applicationId;
    if appUUID is string {
        string?|Application|error application = getApplicationById(appUUID, org);
        if application !is Application {
            string err = "Error while retrieving Application by provided id" + appUUID;
            log:printError(err);
            return error(err);
        }
        string appInString = application.toJsonString();
        json j = check value:fromJsonString(appInString);
        appId = check j.application_id.ensureType();
    }
    string? businessPlan = payload.throttlingPolicy;
    if businessPlan is string {
        string?|error businessPlanID = getBusinessPlanByName(businessPlan);
        if businessPlanID !is string {
            string err = "Error while retrieving BusinessPlan by provided name" + businessPlan;
            log:printError(err);
            return error(err);
        }
        payload.requestedThrottlingPolicy = businessPlan;
    }
    string subscriptionId = uuid:createType1AsString();
    payload.subscriptionId = subscriptionId;
    payload.status = "UNBLOCKED";
    string?|Subscription|error createdSub = addSubscriptionDAO(payload,user,apiId,appId);
    return createdSub;
}

function getBusinessPlanByName(string policyName) returns string?|error {
    string?|error policy = getBusinessPlanByNameDAO(policyName);
    return policy;
}