//! `sse` is a module implementing a Server Sent Events mechanism.
//!
//! This implementation is based on the following
//! [SSE implementation example](https://github.com/actix/examples/tree/master/server-sent-events`).

use std::fmt;

use actix_web_lab::{
    sse::{self, Sse},
    util::InfallibleStream,
};
use serde::Serialize;
use serde_json::value::RawValue;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;

/// Event serializing and sending errors.
#[derive(Debug)]
pub enum Error {
    /// Returned serializing event data failed.
    SerializeError,
}

/// Specifies a type of an event.
///
/// The event types are mapped to different SSE streams. Subscribers
/// use the streams to filter the events they are interested in or to
/// run different processing logic for different types.
#[derive(Debug, PartialEq, Serialize)]
pub enum EventType {
    /// Periodic metrics report has been generated.
    PeriodicReport,
}

/// Event that can be send over the [`EventGateway`].
#[derive(Debug, Serialize)]
pub struct Event {
    event_type: EventType,
    payload: Option<Box<RawValue>>,
}

impl fmt::Display for Event {
    /// Stringifies the event.
    ///
    /// The stringified event is ready to be sent over the wire by the
    /// HTTP server.
    ///
    /// # Errors
    ///
    /// This function returns no error because it is highly unlikely
    /// to have a serialization error at this stage. The payload is
    /// serialized in the [`Event::with_payload`] function. Other fields
    /// should serialize just fine as we rely on the derived serializers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap_or_default())
    }
}

impl Event {
    /// Instantiates new event.
    pub fn new(event_type: EventType) -> Event {
        Self {
            event_type,
            payload: None,
        }
    }

    /// Adds payload to the event.
    ///
    /// The payload holds the optional data for the event. For example,
    /// for the [`EventType::PeriodicReport`] the payload holds the metrics
    /// extracted from the generated report in the JSON format.
    ///
    /// # Errors
    ///
    /// The function may fail when the payload fails during serialization.
    /// This can be a case when it has a custom serializer not using the
    /// derived serde serializers.
    pub fn with_payload<T>(self, payload: T) -> Result<Event, Error>
    where
        T: serde::Serialize,
    {
        let payload = serde_json::to_string(&payload);
        match payload {
            Ok(payload) => {
                let mut event = self;
                event.payload = Some(RawValue::from_string(payload).unwrap());
                Ok(event)
            }
            Err(_) => Err(Error::SerializeError),
        }
    }
}

/// Collects the events in the program and passes them to the HTTP server.
pub struct EventGateway {
    state: Mutex<EventGatewayState>,
}

#[derive(Default)]
struct EventGatewayState {
    clients: Vec<mpsc::Sender<sse::Event>>,
}

impl Default for EventGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl EventGateway {
    /// Instantiates the [`EventGateway`].
    pub fn new() -> Self {
        EventGateway {
            state: Mutex::new(EventGatewayState::default()),
        }
    }

    /// Connects new client.
    ///
    /// It creates a dedicated channel for the connecting client. The channel
    /// is wrapped and returned in the stream used by the HTTP server.
    pub async fn http_new_client(&self) -> Sse<InfallibleStream<ReceiverStream<sse::Event>>> {
        let (tx, rx) = mpsc::channel(10);
        self.state.lock().await.clients.push(tx);
        Sse::from_infallible_receiver(rx)
    }

    /// Sends an event to all subscribers.
    ///
    /// If no clients are subscribed, this function is no-op.
    ///
    /// # Stale Connections
    ///
    /// This function iterates over the open channels and attempts to send
    /// an event copy to all subscribers. If some of the clients hang up
    /// sending the event fails. In this case, the channel to this client
    /// is closed and garbage collected.
    pub async fn send_event(&self, event: Event) {
        let serialized_event = event.to_string();
        let clients = self.state.lock().await.clients.clone();
        if clients.is_empty() {
            return;
        }
        let mut ok_clients = Vec::<mpsc::Sender<sse::Event>>::new();
        for client in clients {
            if client
                .send(sse::Data::new(serialized_event.clone()).into())
                .await
                .is_ok()
            {
                ok_clients.push(client.clone());
            }
        }
        self.state.lock().await.clients = ok_clients;
    }
}

#[cfg(test)]
mod tests {
    use crate::sse::{Event, EventType};
    use assert_json::assert_json;

    use super::EventGateway;

    #[test]
    fn new_event_without_payload() {
        let event = Event::new(EventType::PeriodicReport);
        let serialized_event = event.to_string();
        assert_json!(serialized_event.as_ref(), {
            "event_type": "PeriodicReport"
        });
    }

    #[test]
    fn new_event_with_payload() {
        let event = Event::new(EventType::PeriodicReport).with_payload(123);
        assert!(event.is_ok());
        let event = event.unwrap();
        let serialized_event = event.to_string();
        assert_json!(serialized_event.as_ref(), {
            "event_type": "PeriodicReport",
            "payload":123
        })
    }

    #[tokio::test]
    async fn new_event_gateway_client() {
        let gateway = EventGateway::new();

        // Connect first client.
        let _ = gateway.http_new_client().await;
        assert_eq!(1, gateway.state.lock().await.clients.len());

        // Connect second client. The number of clients should grow.
        let _ = gateway.http_new_client().await;
        assert_eq!(2, gateway.state.lock().await.clients.len());
    }

    #[tokio::test]
    async fn remove_stale_clients() {
        let gateway = EventGateway::new();

        // Connect the first client.
        let _ = gateway.http_new_client().await;
        assert_eq!(1, gateway.state.lock().await.clients.len());

        // Attempt to send an event to this client. Nobody is listening
        // to the events at the other end, so the client should be
        // garbage collected.
        let event = Event::new(EventType::PeriodicReport);
        gateway.send_event(event).await;
        assert_eq!(0, gateway.state.lock().await.clients.len());
    }

    #[tokio::test]
    async fn send_event_no_clients() {
        let gateway = EventGateway::new();

        // Sending an event when no clients are connected should be no-op
        // and not panic.
        let event = Event::new(EventType::PeriodicReport);
        gateway.send_event(event).await;
        assert_eq!(0, gateway.state.lock().await.clients.len());
    }
}
