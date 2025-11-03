#[macro_export]
macro_rules! retry {
    ($f:expr, $count:expr, $interval:expr) => {{
        let mut retries = 1;
        let result = loop {
            let result = $f;
            if result.is_ok() {
                break result;
            } else if retries > $count {
                error!("Failed; giving up after {} attempts", $count);
                break result;
            } else {
                error!(
                    "Failed: {}",
                    result.err().expect("Should always be an error")
                );
                warn!("Attempt {} out of {}", retries, $count);
                retries += 1;
                tokio::time::sleep($interval).await;
            }
        };
        result
    }};
    ($f:expr) => {
        retry!($f, 5, 1000)
    };
}

pub trait Cancellable {
    fn cancel(&mut self);
    fn is_cancelled(&self) -> bool;
}
