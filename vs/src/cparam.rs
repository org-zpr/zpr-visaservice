use crate::error::VSError;
use ::zpr::vsapi::v1 as vsapi;
use std::net::IpAddr;

const IPV4_ADDRESS_SIZE: usize = 4;
const IPV6_ADDRESS_SIZE: usize = 16;

pub const PARAM_ZPR_ADDR: &str = "zpr_addr";
pub const PARAM_AAA_PREFIX: &str = "aaa_prefix";

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
                        if pval.len() != IPV4_ADDRESS_SIZE {
                            return Err(VSError::ParamError(format!(
                                "CParam::from_connect_request: Ipv4 param {} has invalid length {}",
                                pname,
                                pval.len()
                            )));
                        }
                        let mut arr = [0u8; IPV4_ADDRESS_SIZE];
                        arr.copy_from_slice(&pval[0..IPV4_ADDRESS_SIZE]);
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
                        if pval.len() != IPV6_ADDRESS_SIZE {
                            return Err(VSError::ParamError(format!(
                                "CParam::from_connect_request: Ipv6 param {} has invalid length {}",
                                pname,
                                pval.len()
                            )));
                        }
                        let mut arr = [0u8; IPV6_ADDRESS_SIZE];
                        arr.copy_from_slice(&pval[0..IPV6_ADDRESS_SIZE]);
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

    /// Get a string param with given key from a list as a reference.
    pub fn get_string<'a>(params: &'a [CParam], name: &str) -> Result<&'a str, VSError> {
        for pp in params {
            if pp.name == name {
                match &pp.value {
                    CParamValue::String(s) => {
                        return Ok(s);
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

#[cfg(test)]
mod tests {
    use super::*;
    use capnp::message::Builder;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Helper function to create a v_s_connect_request message with the given params
    fn build_connect_request(
        build_fn: impl FnOnce(vsapi::v_s_connect_request::Builder),
    ) -> capnp::message::Reader<capnp::serialize::OwnedSegments> {
        let mut message = Builder::new_default();
        {
            let req = message.init_root::<vsapi::v_s_connect_request::Builder>();
            build_fn(req);
        }
        // Serialize and deserialize to get a Reader
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, &message).unwrap();
        let reader =
            capnp::serialize::read_message(&mut &buf[..], capnp::message::ReaderOptions::new())
                .unwrap();
        reader
    }

    #[test]
    fn test_from_connect_request_empty() {
        let message = build_connect_request(|req| {
            req.init_params(0);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_from_connect_request_single_string() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("test_name");
            param.set_ptype(vsapi::ParamT::String);
            param.set_value_text("test_value");
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "test_name");
        match &result[0].value {
            CParamValue::String(s) => assert_eq!(s, "test_value"),
            _ => panic!("Expected String value"),
        }
    }

    #[test]
    fn test_from_connect_request_single_u64() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("port");
            param.set_ptype(vsapi::ParamT::U64);
            param.set_value_u64(8080);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "port");
        match &result[0].value {
            CParamValue::U64(v) => assert_eq!(*v, 8080),
            _ => panic!("Expected U64 value"),
        }
    }

    #[test]
    fn test_from_connect_request_ipv4() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("zpr_addr");
            param.set_ptype(vsapi::ParamT::Ipv4);
            // 192.168.1.1
            param.set_value_data(&[192, 168, 1, 1]);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "zpr_addr");
        match &result[0].value {
            CParamValue::Ipv4(addr) => {
                assert_eq!(*addr, Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("Expected Ipv4 value"),
        }
    }

    #[test]
    fn test_from_connect_request_ipv6() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("zpr_addr");
            param.set_ptype(vsapi::ParamT::Ipv6);
            // 2001:db8::1
            param.set_value_data(&[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "zpr_addr");
        match &result[0].value {
            CParamValue::Ipv6(addr) => {
                assert_eq!(*addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            }
            _ => panic!("Expected Ipv6 value"),
        }
    }

    #[test]
    fn test_from_connect_request_multiple_params() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(4);

            // String param
            let mut param0 = params.reborrow().get(0);
            param0.set_name("hostname");
            param0.set_ptype(vsapi::ParamT::String);
            param0.set_value_text("server.example.com");

            // U64 param
            let mut param1 = params.reborrow().get(1);
            param1.set_name("port");
            param1.set_ptype(vsapi::ParamT::U64);
            param1.set_value_u64(9999);

            // IPv4 param
            let mut param2 = params.reborrow().get(2);
            param2.set_name("zpr_addr");
            param2.set_ptype(vsapi::ParamT::Ipv4);
            param2.set_value_data(&[10, 0, 0, 1]);

            // IPv6 param
            let mut param3 = params.reborrow().get(3);
            param3.set_name("ipv6_addr");
            param3.set_ptype(vsapi::ParamT::Ipv6);
            param3.set_value_data(&[
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 4);

        // Verify string param
        assert_eq!(result[0].name, "hostname");
        match &result[0].value {
            CParamValue::String(s) => assert_eq!(s, "server.example.com"),
            _ => panic!("Expected String value"),
        }

        // Verify U64 param
        assert_eq!(result[1].name, "port");
        match &result[1].value {
            CParamValue::U64(v) => assert_eq!(*v, 9999),
            _ => panic!("Expected U64 value"),
        }

        // Verify IPv4 param
        assert_eq!(result[2].name, "zpr_addr");
        match &result[2].value {
            CParamValue::Ipv4(addr) => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 1)),
            _ => panic!("Expected Ipv4 value"),
        }

        // Verify IPv6 param
        assert_eq!(result[3].name, "ipv6_addr");
        match &result[3].value {
            CParamValue::Ipv6(addr) => {
                assert_eq!(*addr, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
            }
            _ => panic!("Expected Ipv6 value"),
        }
    }

    #[test]
    fn test_from_connect_request_limit() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(5);
            for i in 0..5 {
                let mut param = params.reborrow().get(i);
                param.set_name(&format!("param{}", i));
                param.set_ptype(vsapi::ParamT::U64);
                param.set_value_u64(i as u64);
            }
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 3).unwrap();

        // Should only return 3 params due to limit
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].name, "param0");
        assert_eq!(result[1].name, "param1");
        assert_eq!(result[2].name, "param2");
    }

    #[test]
    fn test_from_connect_request_ipv4_invalid_length() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("bad_ipv4");
            param.set_ptype(vsapi::ParamT::Ipv4);
            // Wrong length (3 bytes instead of 4)
            param.set_value_data(&[192, 168, 1]);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10);

        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("Ipv4"));
                assert!(msg.contains("invalid length"));
            }
            _ => panic!("Expected ParamError for invalid IPv4 length"),
        }
    }

    #[test]
    fn test_from_connect_request_ipv6_invalid_length() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("bad_ipv6");
            param.set_ptype(vsapi::ParamT::Ipv6);
            // Wrong length (8 bytes instead of 16)
            param.set_value_data(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10);

        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("Ipv6"));
                assert!(msg.contains("invalid length"));
            }
            _ => panic!("Expected ParamError for invalid IPv6 length"),
        }
    }

    #[test]
    fn test_from_connect_request_string_wrong_value_type() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("bad_string");
            param.set_ptype(vsapi::ParamT::String);
            // Set U64 value instead of text
            param.set_value_u64(123);
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10);

        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("String"));
                assert!(msg.contains("invalid value type"));
            }
            _ => panic!("Expected ParamError for wrong value type"),
        }
    }

    #[test]
    fn test_from_connect_request_u64_wrong_value_type() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("bad_u64");
            param.set_ptype(vsapi::ParamT::U64);
            // Set text value instead of U64
            param.set_value_text("not a number");
        });

        let reader = message.get_root().unwrap();
        let result = CParam::from_connect_request(&reader, 10);

        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("U64"));
                assert!(msg.contains("invalid value type"));
            }
            _ => panic!("Expected ParamError for wrong value type"),
        }
    }

    #[test]
    fn test_get_ipaddr_ipv4() {
        let params = vec![CParam {
            name: "zpr_addr".to_string(),
            value: CParamValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        }];

        let result = CParam::get_ipaddr(&params, "zpr_addr").unwrap();
        assert_eq!(result, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_get_ipaddr_ipv6() {
        let params = vec![CParam {
            name: "zpr_addr".to_string(),
            value: CParamValue::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        }];

        let result = CParam::get_ipaddr(&params, "zpr_addr").unwrap();
        assert_eq!(
            result,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_get_ipaddr_not_found() {
        let params = vec![CParam {
            name: "other_param".to_string(),
            value: CParamValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        }];

        let result = CParam::get_ipaddr(&params, "zpr_addr");
        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("not found"));
            }
            _ => panic!("Expected ParamError for not found"),
        }
    }

    #[test]
    fn test_get_ipaddr_wrong_type() {
        let params = vec![CParam {
            name: "zpr_addr".to_string(),
            value: CParamValue::String("not an ip".to_string()),
        }];

        let result = CParam::get_ipaddr(&params, "zpr_addr");
        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("invalid type"));
            }
            _ => panic!("Expected ParamError for invalid type"),
        }
    }

    #[test]
    fn test_get_string() {
        let params = vec![CParam {
            name: "hostname".to_string(),
            value: CParamValue::String("server.example.com".to_string()),
        }];

        let result = CParam::get_string(&params, "hostname").unwrap();
        assert_eq!(result, "server.example.com");
    }

    #[test]
    fn test_get_string_not_found() {
        let params = vec![CParam {
            name: "other_param".to_string(),
            value: CParamValue::String("value".to_string()),
        }];

        let result = CParam::get_string(&params, "hostname");
        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("not found"));
            }
            _ => panic!("Expected ParamError for not found"),
        }
    }

    #[test]
    fn test_get_string_wrong_type() {
        let params = vec![CParam {
            name: "port".to_string(),
            value: CParamValue::U64(8080),
        }];

        let result = CParam::get_string(&params, "port");
        assert!(result.is_err());
        match result {
            Err(VSError::ParamError(msg)) => {
                assert!(msg.contains("invalid type"));
            }
            _ => panic!("Expected ParamError for invalid type"),
        }
    }
}
