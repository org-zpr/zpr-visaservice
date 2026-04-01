use serde::Serialize;

use crate::actor::Actor;
use crate::error::EvalError;
use crate::eval_result::FinalEvalResult;

use zpr::vsapi_types::PacketDesc;

#[derive(Debug)]
pub struct RouteResidualEvaluator {/* TBD */}

#[derive(Serialize, Debug)]
pub struct Route {/* TBD */}

impl RouteResidualEvaluator {
    pub fn eval_route(
        &self,
        _src_actor: &Actor,
        _dst_actor: &Actor,
        _request: &PacketDesc,
        _route: &Route,
    ) -> Result<FinalEvalResult, EvalError> {
        Err(EvalError::InternalError(
            "route evaluation not implemented".to_string(),
        ))
    }

    // TODO: Maybe expose a "route-selector" which could be use in
    // context of topology to prune available routes to only those
    // that match required attributes.
}
