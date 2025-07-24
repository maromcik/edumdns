use crate::error::{CoreError, CoreErrorKind};
use log::info;
use pcap::{Activated, Active, Capture, Device, Offline, State};

pub trait PacketCapture<T>
where
    T: State + Activated,
{
    fn get_capture(self) -> Capture<T>;
    fn apply_filter(&mut self) -> Result<(), CoreError>;
}

pub struct PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    pub capture: Capture<T>,
    pub filter: Option<String>,
}

impl<T> PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    pub fn open_device_capture(
        device_name: &str,
        filter: Option<&str>,
    ) -> Result<PacketCaptureGeneric<Active>, CoreError> {
        let devices = Device::list()?;
        let target = devices
            .into_iter()
            .find(|d| d.name == device_name)
            .ok_or(CoreError::new(
                CoreErrorKind::CaptureError,
                &format!("Capture device {} not found", device_name),
            ))?;
        let target_name = target.name.clone();
        let capture = Capture::from_device(target)?
            .promisc(true)
            .timeout(10000)
            .immediate_mode(true)
            .open()
            .map_err(CoreError::from)?;

        info!("Listening on: {:?}", target_name);

        Ok(PacketCaptureGeneric {
            capture,
            filter: filter.map(|s| s.to_string()),
        })
    }

    pub fn open_file_capture(
        file_path: &str,
        filter: Option<String>,
    ) -> Result<PacketCaptureGeneric<Offline>, CoreError> {
        Ok(PacketCaptureGeneric {
            capture: Capture::from_file(file_path).map_err(CoreError::from)?,
            filter,
        })
    }
}

impl<T> PacketCapture<T> for PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    fn get_capture(self) -> Capture<T> {
        self.capture
    }
    fn apply_filter(&mut self) -> Result<(), CoreError> {
        if let Some(filter) = &self.filter {
            info!("Filter applied: {}", filter);
            self.capture.filter(filter, true)?;
        }
        Ok(())
    }
}
