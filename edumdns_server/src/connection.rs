use crate::error::{ServerError, ServerErrorKind};
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbeConfigElement, ProbeConfigPacket};
use edumdns_core::connection::TcpConnection;

pub struct ConnectionManager {
    connection: TcpConnection,
}

impl ConnectionManager {
    pub async fn connection_init_server(&mut self) -> Result<(), ServerError> {
        let error = Err(ServerError::new(ServerErrorKind::InvalidConnectionInitiation, "invalid connection initiation"));
        let packet = self.receive_init_packet().await?;
        
        let AppPacket::Command(CommandPacket::ProbeHello(hello_uuid)) = packet else {
            return error;       
        };

        // TODO check uuid in DB
        
        let adopted = false;
        if adopted {
            self.connection.send_packet(&AppPacket::Command(CommandPacket::ProbeAdopted)).await?;
        }
        else {
            self.connection.send_packet(&AppPacket::Command(CommandPacket::ProbeUnknown)).await?;    
        }

        let packet = self.receive_init_packet().await?;

        let AppPacket::Command(CommandPacket::ProbeRequestConfig(config_uuid)) = packet else {
            return error;
        };
        
        if config_uuid != hello_uuid {
            return error;   
        }
        
        // TODO pull config from DB

        let probe_config = ProbeConfigElement {
            interface_name: "".to_string(),
            bpf_filter: None,
        };
        
        let probe_config_packet = ProbeConfigPacket {
            interface_filter_map: vec![probe_config]
        };
        self.connection.send_packet(&AppPacket::Command(CommandPacket::ProbeResponseConfig(probe_config_packet))).await?;
        
        Ok(())
    }
    
    pub async fn receive_init_packet(&mut self) -> Result<AppPacket, ServerError> {
        let packet: Option<(AppPacket, usize)> = self.connection.receive_next().await?;
        let Some((app_packet, _)) = packet else {
            return Err(ServerError::new(ServerErrorKind::InvalidConnectionInitiation, "invalid connection initiation"));;
        };
        Ok(app_packet)
    }
}
