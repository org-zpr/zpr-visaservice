use crate::error::VSError;
use ::zpr::vsapi::v1 as vsapi;
use std::net::IpAddr;

/// CParam models the TLV style connect parameters in the initial connect request for a node.
#[derive(Debug, Clone)]
pub struct CParam {
    name: String,
    value: CParamValue,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CParamValue {
    String(String),
    U64(u64),
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
}

impl CParam {
    /// Parse no more than `limit` params out of the connect request.
    pub fn from_connect_request(
        vscr: &vsapi::v_s_connect_request::Reader,
        limit: usize,
    ) -> Result<Vec<CParam>, VSError> {
        let mut results = Vec::new();
        let params = vscr.get_params()?;
        for param in params.iter() {
            let pname = param.get_name()?.to_string()?;
            let ptype = param.get_ptype()?;
            match ptype {
                vsapi::ParamT::String => match param.which()? {
                    vsapi::param::ValueText(foo) => {
                        let pval = foo?;
                        let sval = std::str::from_utf8(pval.as_bytes())?.to_string();
                        results.push(CParam {
                            name: pname,
                            value: CParamValue::String(sval),
                        });
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: String param {} has invalid value type",
                            pname,
                        )));
                    }
                },
                vsapi::ParamT::U64 => match param.which()? {
                    vsapi::param::ValueU64(uval) => {
                        results.push(CParam {
                            name: pname,
                            value: CParamValue::U64(uval),
                        });
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: U64 param {} has invalid value type",
                            pname,
                        )));
                    }
                },
                vsapi::ParamT::Ipv4 => match param.which()? {
                    vsapi::param::ValueData(data) => {
                        let pval = data?;
                        if pval.len() != 4 {
                            return Err(VSError::ParamError(format!(
                                "CParam::from_connect_request: Ipv4 param {} has invalid length {}",
                                pname,
                                pval.len()
                            )));
                        }
                        let mut arr = [0u8; 4];
                        arr.copy_from_slice(&pval[0..4]);
                        let ipv4 = std::net::Ipv4Addr::from(arr);
                        results.push(CParam {
                            name: pname,
                            value: CParamValue::Ipv4(ipv4),
                        });
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: Ipv4 param {} has invalid value type",
                            pname,
                        )));
                    }
                },
                vsapi::ParamT::Ipv6 => match param.which()? {
                    vsapi::param::ValueData(data) => {
                        let pval = data?;
                        if pval.len() != 16 {
                            return Err(VSError::ParamError(format!(
                                "CParam::from_connect_request: Ipv6 param {} has invalid length {}",
                                pname,
                                pval.len()
                            )));
                        }
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&pval[0..16]);
                        let ipv6 = std::net::Ipv6Addr::from(arr);
                        results.push(CParam {
                            name: pname,
                            value: CParamValue::Ipv6(ipv6),
                        });
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: Ipv6 param {} has invalid value type",
                            pname,
                        )));
                    }
                },
            }
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// Helper to extract an IpAddr type param with given key from a list.
    pub fn get_ipaddr(params: &[CParam], name: &str) -> Result<IpAddr, VSError> {
        for pp in params {
            if pp.name == name {
                match &pp.value {
                    CParamValue::Ipv4(ipv4) => {
                        return Ok(IpAddr::V4(*ipv4));
                    }
                    CParamValue::Ipv6(ipv6) => {
                        return Ok(IpAddr::V6(*ipv6));
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "param {name} has invalid type",
                        )));
                    }
                }
            }
        }
        Err(VSError::ParamError(format!("param {name} not found")))
    }

    /// Helper to extract a String type param with given key from a list.
    pub fn get_string(params: &[CParam], name: &str) -> Result<String, VSError> {
        for pp in params {
            if pp.name == name {
                match &pp.value {
                    CParamValue::String(s) => {
                        return Ok(s.clone());
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "param {name} has invalid type",
                        )));
                    }
                }
            }
        }
        Err(VSError::ParamError(format!("param {name} not found")))
    }
}
