use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteSelection {
    pub channel_id: Uuid,
    pub send_enabled: bool,
    pub receive_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingMode {
    Inactive,
    SendOnly,
    ReceiveOnly,
    Sync,
}

pub fn routing_mode(routes: &[RouteSelection]) -> Result<RoutingMode, &'static str> {
    let send: Vec<_> = routes.iter().filter(|route| route.send_enabled).collect();
    let receive: Vec<_> = routes
        .iter()
        .filter(|route| route.receive_enabled)
        .collect();
    match (send.len(), receive.len()) {
        (0, 0) => Ok(RoutingMode::Inactive),
        (_, 0) => Ok(RoutingMode::SendOnly),
        (0, _) => Ok(RoutingMode::ReceiveOnly),
        (1, 1) if send[0].channel_id == receive[0].channel_id => Ok(RoutingMode::Sync),
        _ => Err("invalid ClipMesh routing state"),
    }
}

pub fn add_channel(routes: &mut Vec<RouteSelection>, channel_id: Uuid) {
    if routes.iter().any(|route| route.channel_id == channel_id) {
        return;
    }
    let first = routes.is_empty();
    routes.push(RouteSelection {
        channel_id,
        send_enabled: first,
        receive_enabled: first,
    });
}

pub fn set_route(
    routes: &mut [RouteSelection],
    channel_id: Uuid,
    send: Option<bool>,
    receive: Option<bool>,
) -> Result<(), &'static str> {
    let previous = routes.to_vec();
    let route = routes
        .iter_mut()
        .find(|route| route.channel_id == channel_id)
        .ok_or("unknown channel")?;
    if let Some(value) = send {
        route.send_enabled = value;
    }
    if let Some(value) = receive {
        route.receive_enabled = value;
    }
    if routing_mode(routes).is_err() {
        routes.clone_from_slice(&previous);
        return Err("transition would produce an invalid routing state");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_only_the_four_routing_modes() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut routes = vec![
            RouteSelection {
                channel_id: a,
                send_enabled: true,
                receive_enabled: true,
            },
            RouteSelection {
                channel_id: b,
                send_enabled: false,
                receive_enabled: false,
            },
        ];
        assert_eq!(routing_mode(&routes).unwrap(), RoutingMode::Sync);
        assert!(set_route(&mut routes, b, Some(true), None).is_err());
        assert_eq!(routing_mode(&routes).unwrap(), RoutingMode::Sync);
    }
}
