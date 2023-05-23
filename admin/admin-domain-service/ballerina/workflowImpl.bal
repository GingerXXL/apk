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

import wso2/apk_common_lib as commons;


//This function return the pending workflow list
isolated function getWorkflowList(string? workflowType, int 'limit, int offset, string? accept) returns WorkflowList|commons:APKError{
    WorkflowInfo[]|commons:APKError workflowList = getWorkflowListDAO(workflowType);
    if workflowList is WorkflowInfo[] {
        WorkflowList workflowListResponse = {};
        workflowListResponse.list = workflowList;
        return workflowListResponse;
    } else {
        return workflowList;
    }
}

// This function approvel/reject workflow request
isolated function updateWorkflowStatus(string workflowReferenceId, WorkflowInfo payload) returns OkWorkflowInfo|commons:APKError {
    WorkflowInfo|commons:APKError workflowInfo = getWorkflowDAO(workflowReferenceId, payload);
    OkWorkflowInfo okWorkflowInfo;
    if workflowInfo is WorkflowInfo {
        okWorkflowInfo = {
                body: {
                    workflowReferenceId: workflowInfo.workflowReferenceId
                }
            };
        return okWorkflowInfo;
    } else {
        return e909400(workflowInfo);
    }  
}