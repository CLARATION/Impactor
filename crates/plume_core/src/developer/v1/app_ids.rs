use serde::Deserialize;
use serde_json::{Value, json};

use super::{DeveloperSession, RequestType};
use crate::developer_endpoint;

use crate::Error;

impl DeveloperSession {
    pub async fn v1_list_app_ids(
        &self,
        team: &String,
        filter: Option<&String>,
    ) -> Result<AppIDsResponse, Error> {
        let endpoint = developer_endpoint!("/v1/bundleIds");

        let mut query = String::from("limit=1000");

        if let Some(identifier) = filter {
            query.push_str(&format!("&filter[identifier]={}", identifier));
        }

        let body = json!({
            "teamId": team,
            "urlEncodedQueryParams": query
        });

        let response = self
            .v1_send_request(&endpoint, Some(body), Some(RequestType::Get))
            .await?;
        let response_data: AppIDsResponse = serde_json::from_value(response)?;
        Ok(response_data)
    }

    pub async fn v1_get_app_id(
        &self,
        team: &String,
        app_id: &String,
    ) -> Result<Option<AppID>, Error> {
        let response_data = self.v1_list_app_ids(team, Some(app_id)).await?;

        let app_id = response_data
            .data
            .into_iter()
            .find(|app| app.attributes.identifier == *app_id);

        Ok(app_id)
    }

    pub async fn v1_update_app_id(
        &self,
        team: &String,
        app_id: &String,
        capabilities: Vec<String>,
    ) -> Result<AppIDResponse, Error> {
        let response_data = self.v1_get_app_id(team, app_id).await?;
        let app_id = response_data.ok_or(Error::DeveloperSessionRequestFailed)?;

        let endpoint = developer_endpoint!(&format!("/v1/bundleIds/{}", app_id.id));

        let bundle_id_capabilities: Vec<Value> = capabilities
            .into_iter()
            .map(|capability_id| {
                json!({
                    "type": "bundleIdCapabilities",
                    "attributes": {
                        "enabled": true,
                        "settings": []
                    },
                    "relationships": {
                        "capability": {
                            "data": {
                                "type": "capabilities",
                                "id": capability_id
                            }
                        }
                    }
                })
            })
            .collect();

        let payload = json!({
            "data": {
                "type": "bundleIds",
                "id": app_id.id,
                "attributes": {
                    "identifier": app_id.attributes.identifier,
                    "seedId": app_id.attributes.seed_id,
                    "teamId": team,
                    "name": app_id.attributes.name,
                    "wildcard": app_id.attributes.wildcard,
                },
                "relationships": {
                    "bundleIdCapabilities": {
                        "data": bundle_id_capabilities
                    }
                }
            }
        });

        let response = self
            .v1_send_request(&endpoint, Some(payload), Some(RequestType::Patch))
            .await?;
        let response_data: AppIDResponse = serde_json::from_value(response)?;

        Ok(response_data)
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppIDsResponse {
    pub data: Vec<AppID>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppIDResponse {
    pub data: AppID,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppID {
    pub id: String,
    pub attributes: AppIDAttributes,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppIDAttributes {
    pub identifier: String,
    pub seed_id: String,
    pub has_exclusive_managed_capabilities: bool,
    pub name: String,
    // pub entitlement_group_name: Option<String>,
    pub bundle_type: String,
    // pub entitlement_types: Option<String>,
    // pub platform: Option<String>,
    // pub deployment_data_notice: Option<String>,
    // pub response_id: Option<String>,
    pub wildcard: bool,
}
