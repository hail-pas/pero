pub use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};

pub fn set_request_id_layer() -> SetRequestIdLayer<MakeRequestUuid> {
    SetRequestIdLayer::x_request_id(MakeRequestUuid)
}

pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::x_request_id()
}
