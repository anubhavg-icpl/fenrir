use serde::{Serialize, Deserialize};
use crate::Event;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionPattern {
    ProcessInjection,
    CredentialDumping,
    LateralMovement,
    Persistence,
    DefenseEvasion,
    PrivilegeEscalation,
    CommandAndControl,
    Exfiltration,
}

pub struct PatternMatcher;

impl PatternMatcher {
    pub fn new() -> Self {
        Self
    }

    pub fn matches(&self, pattern: &DetectionPattern, event: &Event) -> bool {
        match pattern {
            DetectionPattern::ProcessInjection => self.check_process_injection(event),
            DetectionPattern::CredentialDumping => self.check_credential_dumping(event),
            DetectionPattern::LateralMovement => self.check_lateral_movement(event),
            DetectionPattern::Persistence => self.check_persistence(event),
            DetectionPattern::DefenseEvasion => self.check_defense_evasion(event),
            DetectionPattern::PrivilegeEscalation => self.check_privilege_escalation(event),
            DetectionPattern::CommandAndControl => self.check_command_and_control(event),
            DetectionPattern::Exfiltration => self.check_exfiltration(event),
        }
    }

    fn check_process_injection(&self, event: &Event) -> bool {
        if let Event::Process(p) = event {
            let suspicious_processes = ["svchost.exe", "rundll32.exe", "regsvr32.exe"];
            let injection_indicators = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
            
            let name_match = suspicious_processes.iter()
                .any(|&name| p.process_name.to_lowercase().contains(name));
            
            let cmd_match = injection_indicators.iter()
                .any(|&indicator| p.command_line.contains(indicator));
            
            name_match && cmd_match
        } else {
            false
        }
    }

    fn check_credential_dumping(&self, event: &Event) -> bool {
        if let Event::Process(p) = event {
            let dumping_tools = ["mimikatz", "lazagne", "procdump", "pwdump"];
            let lsass_access = p.command_line.contains("lsass.exe");
            
            dumping_tools.iter()
                .any(|&tool| p.process_name.to_lowercase().contains(tool) || 
                            p.command_line.to_lowercase().contains(tool))
                || lsass_access
        } else {
            false
        }
    }

    fn check_lateral_movement(&self, event: &Event) -> bool {
        if let Event::Network(n) = event {
            let lateral_ports = [445, 135, 139, 3389, 22, 5985, 5986];
            lateral_ports.contains(&n.remote_port)
        } else if let Event::Process(p) = event {
            let lateral_tools = ["psexec", "wmic", "winrm", "ssh", "rdp"];
            lateral_tools.iter()
                .any(|&tool| p.process_name.to_lowercase().contains(tool) ||
                            p.command_line.to_lowercase().contains(tool))
        } else {
            false
        }
    }

    fn check_persistence(&self, event: &Event) -> bool {
        if let Event::File(f) = event {
            let persistence_paths = [
                "\\Startup\\",
                "\\Run\\",
                "\\RunOnce\\",
                "\\Services\\",
                "\\Tasks\\",
                "/etc/cron",
                "/etc/systemd/system",
            ];
            
            persistence_paths.iter()
                .any(|&path| f.file_path.contains(path))
        } else if let Event::Process(p) = event {
            let persistence_commands = ["schtasks", "at", "crontab", "systemctl"];
            persistence_commands.iter()
                .any(|&cmd| p.process_name.contains(cmd) || p.command_line.contains(cmd))
        } else {
            false
        }
    }

    fn check_defense_evasion(&self, event: &Event) -> bool {
        if let Event::Process(p) = event {
            let evasion_indicators = [
                "base64",
                "compress",
                "encode",
                "obfuscat",
                "-enc",
                "-e",
                "bypass",
                "amsi",
                "defender",
            ];
            
            evasion_indicators.iter()
                .any(|&indicator| p.command_line.to_lowercase().contains(indicator))
        } else {
            false
        }
    }

    fn check_privilege_escalation(&self, event: &Event) -> bool {
        if let Event::Process(p) = event {
            let privesc_indicators = [
                "runas",
                "sudo",
                "UAC",
                "privileges",
                "SeDebugPrivilege",
                "admin",
                "elevation",
            ];
            
            privesc_indicators.iter()
                .any(|&indicator| p.command_line.to_lowercase().contains(indicator))
        } else {
            false
        }
    }

    fn check_command_and_control(&self, event: &Event) -> bool {
        if let Event::Network(n) = event {
            let c2_ports = [80, 443, 8080, 8443, 1337, 4444, 8888];
            let suspicious_tld = [".tk", ".ml", ".ga", ".cf"];
            
            let port_match = c2_ports.contains(&n.remote_port);
            let domain_match = suspicious_tld.iter()
                .any(|&tld| n.remote_address.ends_with(tld));
            
            port_match || domain_match
        } else {
            false
        }
    }

    fn check_exfiltration(&self, event: &Event) -> bool {
        if let Event::Network(n) = event {
            let exfil_ports = [21, 22, 25, 110, 443, 993, 995];
            exfil_ports.contains(&n.remote_port)
        } else if let Event::Process(p) = event {
            let exfil_tools = ["curl", "wget", "ftp", "scp", "rsync"];
            exfil_tools.iter()
                .any(|&tool| p.process_name.contains(tool) || p.command_line.contains(tool))
        } else {
            false
        }
    }
}