use plist::{Data, Date, Dictionary, Integer, Value};
use serde::Deserialize;
use uuid::Uuid;

use crate::Error;

use super::{DeveloperSession, QHResponseMeta};
use crate::developer_endpoint;

impl DeveloperSession {
    pub async fn qh_list_certs(&self, team_id: &String) -> Result<CertsResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/listAllDevelopmentCerts.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: CertsResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }

    pub async fn qh_revoke_cert(
        &self,
        team_id: &String,
        serial_number: &String,
    ) -> Result<QHResponseMeta, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/revokeDevelopmentCert.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));
        body.insert(
            "serialNumber".to_string(),
            Value::String(serial_number.clone()),
        );

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: QHResponseMeta = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }

    pub async fn qh_submit_cert_csr(
        &self,
        team_id: &String,
        csr_data: String,
        machine_name: &String,
    ) -> Result<CsrResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/submitDevelopmentCSR.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));
        body.insert("csrContent".to_string(), Value::String(csr_data));
        body.insert(
            "machineId".to_string(),
            Value::String(Uuid::new_v4().to_string().to_uppercase()),
        );
        body.insert(
            "machineName".to_string(),
            Value::String(machine_name.clone()),
        );

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: CsrResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CertsResponse {
    pub certificates: Vec<Cert>,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CsrResponse {
    pub cert_request: Csr,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cert {
    pub name: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub status: String,
    status_code: Integer,
    pub expiration_date: Date,
    certificate_platform: Option<String>,
    pub cert_type: Option<CertType>,
    pub cert_content: Option<Data>,
    pub machine_id: Option<String>,
    pub machine_name: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Csr {
    cert_request_id: String,
    name: String,
    status_code: Integer,
    status_string: String,
    csr_platform: String,
    date_requested_string: String,
    date_requested: Date,
    date_created: Date,
    owner_type: String,
    owner_name: String,
    owner_id: String,
    pub certificate_id: String,
    certificate_status_code: Integer,
    cert_request_status_code: Integer,
    certificate_type_display_id: String,
    pub serial_num: String,
    serial_num_decimal: String,
    type_string: String,
    pub certificate_type: Option<CertType>,
    pub machine_id: Option<String>,
    pub machine_name: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertType {
    certificate_type_display_id: String,
    pub name: String,
    platform: String,
    permission_type: String,
    distribution_method: String,
    owner_type: String,
    days_overlap: Integer,
    max_active: Integer,
}
